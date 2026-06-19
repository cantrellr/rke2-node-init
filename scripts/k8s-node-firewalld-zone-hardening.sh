#!/usr/bin/env bash
# shellcheck shell=bash
#
# k8s-node-firewalld-zone-hardening.sh
#
# Purpose:
#   Harden a multi-homed Ubuntu 24.04 LTS Kubernetes node using firewalld zones,
#   interface binding, host network sysctl hardening, and optional Kubernetes/RKE2
#   port allowances.
#
# Designed baseline:
#   ens33 -> domain network    10.0.4.0/24     default-gateway interface
#   ens35 -> storage network   172.16.0.0/24   no gateway
#   ens36 -> onprem network    1.0.1.0/24      no gateway
#   ens37 -> hypermute network 10.22.0.0/24    no gateway
#
# Security model:
#   - Create one firewalld zone per NIC.
#   - Assign each NIC to its expected zone.
#   - Set all managed zones to target DROP.
#   - Allow only explicitly defined inbound traffic.
#   - Disable UFW to avoid conflicting firewall managers.
#   - Disable IPv4/IPv6 forwarding and unsafe redirects/source-routing.
#   - Optionally create firewalld HOST -> zone policy objects to restrict
#     host-originated traffic toward non-default networks to their expected CIDRs.
#   - Do not enable masquerading/NAT.
#
# Kubernetes note:
#   This script includes an RKE2-oriented allow-list. The default node role is
#   "auto". If rke2-server.service is detected, server ports are allowed from
#   the Kubernetes source CIDR. If rke2-agent.service is detected, agent/common
#   ports are allowed. If neither exists yet, common RKE2 node ports are allowed.
#
#   This is intentionally conservative. It does not open NodePort ranges unless
#   --open-nodeports is specified.
#
# Repeatability:
#   The script is idempotent. By default, it recreates the four managed custom
#   zones and managed host-egress policies on each run so the resulting policy is
#   deterministic. Existing non-managed firewalld zones are not deleted.
#
# Logging:
#   Every action and command output is logged to:
#     /var/log/k8s-firewalld-hardening/k8s-firewalld-hardening-<timestamp>.log
#   A latest.log symlink is also maintained.
#
# Usage examples:
#   sudo ./k8s-node-firewalld-zone-hardening.sh --yes
#
#   sudo ./k8s-node-firewalld-zone-hardening.sh --yes --node-role server
#
#   sudo ./k8s-node-firewalld-zone-hardening.sh --yes --node-role agent
#
#   sudo ./k8s-node-firewalld-zone-hardening.sh --dry-run --node-role server
#
#   sudo ./k8s-node-firewalld-zone-hardening.sh --yes \
#     --allow-storage-tcp 2049,111 --allow-storage-udp 111
#
# Rollback:
#   sudo firewall-cmd --permanent --delete-zone=domain 2>/dev/null || true
#   sudo firewall-cmd --permanent --delete-zone=storage 2>/dev/null || true
#   sudo firewall-cmd --permanent --delete-zone=onprem 2>/dev/null || true
#   sudo firewall-cmd --permanent --delete-zone=hypermute 2>/dev/null || true
#   sudo firewall-cmd --permanent --delete-policy=h2storage 2>/dev/null || true
#   sudo firewall-cmd --permanent --delete-policy=h2onprem 2>/dev/null || true
#   sudo firewall-cmd --permanent --delete-policy=h2hyper 2>/dev/null || true
#   sudo firewall-cmd --reload
#
# Exit codes:
#   0 - Success
#   1 - General/runtime error
#   2 - Invalid argument/configuration
#   3 - Preflight failure

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="/var/log/k8s-firewalld-hardening"
LOG_FILE="${LOG_DIR}/k8s-firewalld-hardening-${TIMESTAMP}.log"
LATEST_LOG="${LOG_DIR}/latest.log"

# -----------------------------
# Defaults - edit only if you do not want to use CLI flags.
# -----------------------------
DOMAIN_IF="ens33"
STORAGE_IF="ens35"
ONPREM_IF="ens36"
HYPERMUTE_IF="ens37"

DOMAIN_CIDR="10.0.4.0/24"
STORAGE_CIDR="172.16.0.0/24"
ONPREM_CIDR="1.0.1.0/24"
HYPERMUTE_CIDR="10.22.0.0/24"

# Source CIDR allowed to manage the node over SSH.
SSH_SOURCE_CIDR="10.0.4.0/24"
SSH_PORT="22"

# Source CIDR allowed to reach Kubernetes/RKE2 node ports.
# Usually this should be the node/domain network, not every network.
K8S_SOURCE_CIDR="10.0.4.0/24"
NODE_ROLE="auto"          # auto | server | agent | common | none
OPEN_NODEPORTS="false"   # true | false

# Optional inbound application allowances per zone.
# Values are comma-separated port/range strings, e.g. 2049,111,30000-32767
ALLOW_DOMAIN_TCP=""
ALLOW_DOMAIN_UDP=""
ALLOW_STORAGE_TCP=""
ALLOW_STORAGE_UDP=""
ALLOW_ONPREM_TCP=""
ALLOW_ONPREM_UDP=""
ALLOW_HYPERMUTE_TCP=""
ALLOW_HYPERMUTE_UDP=""

# Behavior controls.
ASSUME_YES="false"
DRY_RUN="false"
INSTALL_FIREWALLD="true"
DISABLE_UFW="true"
APPLY_SYSCTL="true"
RESET_MANAGED_ZONES="true"
CREATE_HOST_EGRESS_POLICIES="true"
BACKUP_FIREWALLD="true"
VERBOSE="false"

# Managed object names. Policy names are short because firewalld policy filenames
# have a conservative length constraint on many distributions.
DOMAIN_ZONE="domain"
STORAGE_ZONE="storage"
ONPREM_ZONE="onprem"
HYPERMUTE_ZONE="hypermute"
HOST_TO_STORAGE_POLICY="h2storage"
HOST_TO_ONPREM_POLICY="h2onprem"
HOST_TO_HYPERMUTE_POLICY="h2hyper"

# RKE2/Kubernetes ports. Adjust only if your CNI or runtime requires different ports.
# Common:
#   10250/tcp = kubelet API
#   8472/udp  = Flannel/Canal VXLAN on many RKE2 deployments
# Server:
#   6443/tcp      = Kubernetes API server
#   9345/tcp      = RKE2 supervisor
#   2379-2380/tcp = etcd peer/client among server nodes
K8S_COMMON_TCP_PORTS=("10250")
K8S_COMMON_UDP_PORTS=("8472")
K8S_SERVER_TCP_PORTS=("6443" "9345" "2379-2380")
K8S_SERVER_UDP_PORTS=()
NODEPORT_TCP_PORTS=("30000-32767")
NODEPORT_UDP_PORTS=("30000-32767")

# -----------------------------
# Logging and runtime helpers
# -----------------------------

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
ln -sfn "$LOG_FILE" "$LATEST_LOG"

# From this point forward, every stdout/stderr line is captured.
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
  local level="$1"
  shift
  printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$level" "$*"
}

info() { log "INFO" "$*"; }
warn() { log "WARN" "$*"; }
error() { log "ERROR" "$*"; }

usage() {
  cat <<'USAGE'
Usage:
  sudo ./k8s-node-firewalld-zone-hardening.sh [options]

Required for non-interactive execution:
  --yes                         Apply changes without interactive confirmation.

Core options:
  --domain-if IFACE             Domain/default-gateway NIC. Default: ens33
  --storage-if IFACE            Storage NIC. Default: ens35
  --onprem-if IFACE             Onprem NIC. Default: ens36
  --hypermute-if IFACE          Hypermute NIC. Default: ens37

  --domain-cidr CIDR            Domain network CIDR. Default: 10.0.4.0/24
  --storage-cidr CIDR           Storage network CIDR. Default: 172.16.0.0/24
  --onprem-cidr CIDR            Onprem network CIDR. Default: 1.0.1.0/24
  --hypermute-cidr CIDR         Hypermute network CIDR. Default: 10.22.0.0/24

Access options:
  --ssh-source-cidr CIDR        CIDR allowed to SSH to this node. Default: 10.0.4.0/24
  --ssh-port PORT               SSH port. Default: 22
  --k8s-source-cidr CIDR        CIDR allowed to reach Kubernetes/RKE2 node ports. Default: 10.0.4.0/24
  --node-role ROLE              auto | server | agent | common | none. Default: auto
  --open-nodeports              Allow Kubernetes NodePort range 30000-32767 TCP/UDP from --k8s-source-cidr.

Optional inbound zone allowances:
  --allow-domain-tcp PORTS      Comma-separated TCP ports/ranges allowed into domain zone.
  --allow-domain-udp PORTS      Comma-separated UDP ports/ranges allowed into domain zone.
  --allow-storage-tcp PORTS     Comma-separated TCP ports/ranges allowed into storage zone.
  --allow-storage-udp PORTS     Comma-separated UDP ports/ranges allowed into storage zone.
  --allow-onprem-tcp PORTS      Comma-separated TCP ports/ranges allowed into onprem zone.
  --allow-onprem-udp PORTS      Comma-separated UDP ports/ranges allowed into onprem zone.
  --allow-hypermute-tcp PORTS   Comma-separated TCP ports/ranges allowed into hypermute zone.
  --allow-hypermute-udp PORTS   Comma-separated UDP ports/ranges allowed into hypermute zone.

Behavior controls:
  --dry-run                     Log what would be done, but do not change the system.
  --no-install                  Do not install firewalld if missing.
  --no-disable-ufw              Do not disable UFW.
  --no-sysctl                   Do not apply sysctl hardening.
  --no-reset-managed-zones      Do not delete/recreate managed zones before applying config.
  --no-host-egress-policies     Do not create HOST -> non-default-zone egress policies.
  --no-backup                   Do not back up /etc/firewalld before changes.
  --verbose                     Extra diagnostic logging.
  --help                        Show this help.

Examples:
  sudo ./k8s-node-firewalld-zone-hardening.sh --yes --node-role server
  sudo ./k8s-node-firewalld-zone-hardening.sh --yes --node-role agent
  sudo ./k8s-node-firewalld-zone-hardening.sh --dry-run --node-role server

USAGE
}

run_cmd() {
  # Logs and executes a command. In dry-run mode, only logs.
  local cmd=("$@")
  info "RUN: ${cmd[*]}"
  if [[ "$DRY_RUN" == "true" ]]; then
    return 0
  fi
  "${cmd[@]}"
}

run_bash() {
  # Logs and executes a shell command string. Use sparingly; prefer run_cmd.
  local command_string="$1"
  info "RUN: ${command_string}"
  if [[ "$DRY_RUN" == "true" ]]; then
    return 0
  fi
  bash -c "$command_string"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    error "This script must be run as root. Use sudo."
    exit 3
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

valid_cidr() {
  local cidr="$1"
  [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]
}

valid_port_or_range() {
  local p="$1"
  [[ "$p" =~ ^[0-9]{1,5}(-[0-9]{1,5})?$ ]]
}

validate_port_list() {
  local label="$1"
  local list="$2"
  [[ -z "$list" ]] && return 0

  local item
  IFS=',' read -r -a items <<< "$list"
  for item in "${items[@]}"; do
    item="${item//[[:space:]]/}"
    if ! valid_port_or_range "$item"; then
      error "Invalid ${label} port/range: ${item}"
      exit 2
    fi
  done
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes) ASSUME_YES="true"; shift ;;
      --dry-run) DRY_RUN="true"; shift ;;
      --domain-if) DOMAIN_IF="${2:?Missing value for --domain-if}"; shift 2 ;;
      --storage-if) STORAGE_IF="${2:?Missing value for --storage-if}"; shift 2 ;;
      --onprem-if) ONPREM_IF="${2:?Missing value for --onprem-if}"; shift 2 ;;
      --hypermute-if) HYPERMUTE_IF="${2:?Missing value for --hypermute-if}"; shift 2 ;;
      --domain-cidr) DOMAIN_CIDR="${2:?Missing value for --domain-cidr}"; shift 2 ;;
      --storage-cidr) STORAGE_CIDR="${2:?Missing value for --storage-cidr}"; shift 2 ;;
      --onprem-cidr) ONPREM_CIDR="${2:?Missing value for --onprem-cidr}"; shift 2 ;;
      --hypermute-cidr) HYPERMUTE_CIDR="${2:?Missing value for --hypermute-cidr}"; shift 2 ;;
      --ssh-source-cidr) SSH_SOURCE_CIDR="${2:?Missing value for --ssh-source-cidr}"; shift 2 ;;
      --ssh-port) SSH_PORT="${2:?Missing value for --ssh-port}"; shift 2 ;;
      --k8s-source-cidr) K8S_SOURCE_CIDR="${2:?Missing value for --k8s-source-cidr}"; shift 2 ;;
      --node-role) NODE_ROLE="${2:?Missing value for --node-role}"; shift 2 ;;
      --open-nodeports) OPEN_NODEPORTS="true"; shift ;;
      --allow-domain-tcp) ALLOW_DOMAIN_TCP="${2:?Missing value for --allow-domain-tcp}"; shift 2 ;;
      --allow-domain-udp) ALLOW_DOMAIN_UDP="${2:?Missing value for --allow-domain-udp}"; shift 2 ;;
      --allow-storage-tcp) ALLOW_STORAGE_TCP="${2:?Missing value for --allow-storage-tcp}"; shift 2 ;;
      --allow-storage-udp) ALLOW_STORAGE_UDP="${2:?Missing value for --allow-storage-udp}"; shift 2 ;;
      --allow-onprem-tcp) ALLOW_ONPREM_TCP="${2:?Missing value for --allow-onprem-tcp}"; shift 2 ;;
      --allow-onprem-udp) ALLOW_ONPREM_UDP="${2:?Missing value for --allow-onprem-udp}"; shift 2 ;;
      --allow-hypermute-tcp) ALLOW_HYPERMUTE_TCP="${2:?Missing value for --allow-hypermute-tcp}"; shift 2 ;;
      --allow-hypermute-udp) ALLOW_HYPERMUTE_UDP="${2:?Missing value for --allow-hypermute-udp}"; shift 2 ;;
      --no-install) INSTALL_FIREWALLD="false"; shift ;;
      --no-disable-ufw) DISABLE_UFW="false"; shift ;;
      --no-sysctl) APPLY_SYSCTL="false"; shift ;;
      --no-reset-managed-zones) RESET_MANAGED_ZONES="false"; shift ;;
      --no-host-egress-policies) CREATE_HOST_EGRESS_POLICIES="false"; shift ;;
      --no-backup) BACKUP_FIREWALLD="false"; shift ;;
      --verbose) VERBOSE="true"; shift ;;
      --help|-h) usage; exit 0 ;;
      *) error "Unknown option: $1"; usage; exit 2 ;;
    esac
  done
}

validate_config() {
  info "Validating configuration input."

  local role
  role="$(printf '%s' "$NODE_ROLE" | tr '[:upper:]' '[:lower:]')"
  case "$role" in
    auto|server|agent|common|none) NODE_ROLE="$role" ;;
    *) error "Invalid --node-role: ${NODE_ROLE}. Valid values: auto, server, agent, common, none."; exit 2 ;;
  esac

  for cidr in "$DOMAIN_CIDR" "$STORAGE_CIDR" "$ONPREM_CIDR" "$HYPERMUTE_CIDR" "$SSH_SOURCE_CIDR" "$K8S_SOURCE_CIDR"; do
    if ! valid_cidr "$cidr"; then
      error "Invalid CIDR: ${cidr}"
      exit 2
    fi
  done

  if ! [[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]]; then
    error "Invalid SSH port: ${SSH_PORT}"
    exit 2
  fi

  validate_port_list "domain tcp" "$ALLOW_DOMAIN_TCP"
  validate_port_list "domain udp" "$ALLOW_DOMAIN_UDP"
  validate_port_list "storage tcp" "$ALLOW_STORAGE_TCP"
  validate_port_list "storage udp" "$ALLOW_STORAGE_UDP"
  validate_port_list "onprem tcp" "$ALLOW_ONPREM_TCP"
  validate_port_list "onprem udp" "$ALLOW_ONPREM_UDP"
  validate_port_list "hypermute tcp" "$ALLOW_HYPERMUTE_TCP"
  validate_port_list "hypermute udp" "$ALLOW_HYPERMUTE_UDP"

  local ifaces=("$DOMAIN_IF" "$STORAGE_IF" "$ONPREM_IF" "$HYPERMUTE_IF")
  local unique
  unique="$(printf '%s\n' "${ifaces[@]}" | sort -u | wc -l)"
  if [[ "$unique" -ne 4 ]]; then
    error "NIC names must be unique. Current: ${ifaces[*]}"
    exit 2
  fi

  if [[ "$ASSUME_YES" != "true" && "$DRY_RUN" != "true" ]]; then
    warn "This script will change firewalld, UFW, and sysctl settings."
    read -r -p "Type YES to continue: " response
    if [[ "$response" != "YES" ]]; then
      error "User aborted."
      exit 1
    fi
  fi
}

preflight() {
  info "Starting preflight checks."
  info "Script: ${SCRIPT_NAME}"
  info "Log file: ${LOG_FILE}"
  info "Dry run: ${DRY_RUN}"

  local iface
  for iface in "$DOMAIN_IF" "$STORAGE_IF" "$ONPREM_IF" "$HYPERMUTE_IF"; do
    if ! ip link show "$iface" >/dev/null 2>&1; then
      error "Required interface not found: ${iface}"
      exit 3
    fi
  done

  local default_count
  default_count="$(ip route show default 2>/dev/null | wc -l | tr -d ' ')"
  info "Default route count: ${default_count}"
  ip route show default || true

  if [[ "$default_count" -ne 1 ]]; then
    warn "Expected exactly one default route. Found ${default_count}. Validate netplan before production rollout."
  fi

  if ! ip route show default | grep -q "dev ${DOMAIN_IF}"; then
    warn "Default route does not appear to use ${DOMAIN_IF}. This script will continue, but your routing design may be wrong."
  fi

  info "Current interface summary:"
  ip -brief address || true

  info "Current route table:"
  ip route || true

  if [[ "$VERBOSE" == "true" ]]; then
    info "Current sysctl values of interest:"
    sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter || true
  fi
}

install_and_start_firewalld() {
  if command_exists firewall-cmd; then
    info "firewall-cmd is already installed."
  else
    if [[ "$INSTALL_FIREWALLD" != "true" ]]; then
      error "firewalld is not installed and --no-install was specified."
      exit 3
    fi
    info "Installing firewalld."
    run_cmd apt-get update
    run_cmd apt-get install -y firewalld
  fi

  info "Enabling and starting firewalld."
  run_cmd systemctl enable --now firewalld

  if [[ "$DRY_RUN" != "true" ]]; then
    if ! firewall-cmd --state >/dev/null 2>&1; then
      error "firewalld is not running after start attempt."
      exit 3
    fi
  fi
}

disable_ufw_if_requested() {
  if [[ "$DISABLE_UFW" != "true" ]]; then
    warn "Skipping UFW disable because --no-disable-ufw was specified. Do not run UFW and firewalld together unless you have a specific reason."
    return 0
  fi

  if command_exists ufw; then
    info "Disabling UFW to avoid conflicting firewall managers."
    run_cmd ufw --force disable
    if systemctl list-unit-files ufw.service >/dev/null 2>&1; then
      run_cmd systemctl disable ufw || true
    fi
  else
    info "UFW is not installed; nothing to disable."
  fi
}

backup_firewalld_config() {
  if [[ "$BACKUP_FIREWALLD" != "true" ]]; then
    info "Skipping /etc/firewalld backup because --no-backup was specified."
    return 0
  fi

  if [[ -d /etc/firewalld ]]; then
    local backup_dir="/etc/firewalld.backup.${TIMESTAMP}"
    info "Backing up /etc/firewalld to ${backup_dir}."
    run_cmd cp -a /etc/firewalld "$backup_dir"
  else
    info "/etc/firewalld does not exist yet; no backup needed."
  fi
}

write_sysctl_hardening() {
  if [[ "$APPLY_SYSCTL" != "true" ]]; then
    info "Skipping sysctl hardening because --no-sysctl was specified."
    return 0
  fi

  local sysctl_file="/etc/sysctl.d/90-k8s-multinic-firewalld-hardening.conf"
  info "Writing sysctl hardening file: ${sysctl_file}"

  if [[ "$DRY_RUN" == "true" ]]; then
    info "DRY-RUN: would write ${sysctl_file}."
  else
    cat > "$sysctl_file" <<SYSCTL
# Managed by ${SCRIPT_NAME} on ${TIMESTAMP}
# Purpose: Prevent this multi-homed Kubernetes node from acting as a router
# or accepting unsafe network behaviors across domain/storage/onprem/hypermute NICs.

# Do not route traffic between NICs.
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

# Do not send ICMP redirects.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Do not accept ICMP redirects.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not accept source-routed packets.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Reverse path filtering helps reduce spoofing on a non-routing host.
# Strict mode is used because this host should not be routing asymmetrically.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.${DOMAIN_IF}.rp_filter = 1
net.ipv4.conf.${STORAGE_IF}.rp_filter = 1
net.ipv4.conf.${ONPREM_IF}.rp_filter = 1
net.ipv4.conf.${HYPERMUTE_IF}.rp_filter = 1

# Log martian packets for troubleshooting spoofing/routing problems.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Reduce ARP flux on multi-NIC hosts.
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2
SYSCTL
  fi

  run_cmd sysctl --system
}

firewalld_has_policy_support() {
  firewall-cmd --help 2>/dev/null | grep -q -- '--new-policy'
}

fw_zone_exists() {
  local zone="$1"
  firewall-cmd --permanent --get-zones 2>/dev/null | tr ' ' '\n' | grep -qx "$zone"
}

fw_policy_exists() {
  local policy="$1"
  firewall-cmd --permanent --get-policies 2>/dev/null | tr ' ' '\n' | grep -qx "$policy"
}

reset_managed_firewalld_objects() {
  if [[ "$RESET_MANAGED_ZONES" != "true" ]]; then
    info "Skipping managed zone/policy reset because --no-reset-managed-zones was specified."
    return 0
  fi

  info "Resetting managed firewalld zones and policies for deterministic output."

  # Remove host egress policies first.
  if firewalld_has_policy_support; then
    local policy
    for policy in "$HOST_TO_STORAGE_POLICY" "$HOST_TO_ONPREM_POLICY" "$HOST_TO_HYPERMUTE_POLICY"; do
      if [[ "$DRY_RUN" == "true" ]] || fw_policy_exists "$policy"; then
        run_cmd firewall-cmd --permanent --delete-policy="$policy" || true
      fi
    done
  fi

  # Remove interface bindings and delete custom zones.
  local zone iface
  for zone in "$DOMAIN_ZONE" "$STORAGE_ZONE" "$ONPREM_ZONE" "$HYPERMUTE_ZONE"; do
    for iface in "$DOMAIN_IF" "$STORAGE_IF" "$ONPREM_IF" "$HYPERMUTE_IF"; do
      run_cmd firewall-cmd --permanent --zone="$zone" --remove-interface="$iface" || true
      run_cmd firewall-cmd --zone="$zone" --remove-interface="$iface" || true
    done
    if [[ "$DRY_RUN" == "true" ]] || fw_zone_exists "$zone"; then
      run_cmd firewall-cmd --permanent --delete-zone="$zone" || true
    fi
  done

  run_cmd firewall-cmd --reload
}

create_zone() {
  local zone="$1"
  local iface="$2"
  local description="$3"

  info "Creating managed zone ${zone} for interface ${iface}."
  if [[ "$DRY_RUN" == "true" ]] || ! fw_zone_exists "$zone"; then
    run_cmd firewall-cmd --permanent --new-zone="$zone"
  fi

  run_cmd firewall-cmd --permanent --zone="$zone" --set-target=DROP
  run_cmd firewall-cmd --permanent --zone="$zone" --set-description="$description"
  run_cmd firewall-cmd --permanent --zone="$zone" --set-short="$zone"

  # --change-interface moves the interface if it already belongs to another zone.
  run_cmd firewall-cmd --permanent --zone="$zone" --change-interface="$iface"
}

add_zone_rich_rule() {
  local zone="$1"
  local rule="$2"
  run_cmd firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rule"
}

add_inbound_port_from_cidr() {
  local zone="$1"
  local source_cidr="$2"
  local port="$3"
  local proto="$4"
  local label="$5"

  info "Allowing inbound ${proto}/${port} into zone ${zone} from ${source_cidr} (${label})."
  add_zone_rich_rule "$zone" "rule family=\"ipv4\" source address=\"${source_cidr}\" port port=\"${port}\" protocol=\"${proto}\" accept"
}

add_port_list_to_zone() {
  local zone="$1"
  local source_cidr="$2"
  local proto="$3"
  local list="$4"
  local label="$5"

  [[ -z "$list" ]] && return 0
  local port
  IFS=',' read -r -a ports <<< "$list"
  for port in "${ports[@]}"; do
    port="${port//[[:space:]]/}"
    add_inbound_port_from_cidr "$zone" "$source_cidr" "$port" "$proto" "$label"
  done
}

resolve_node_role() {
  if [[ "$NODE_ROLE" != "auto" ]]; then
    echo "$NODE_ROLE"
    return 0
  fi

  if systemctl list-unit-files rke2-server.service >/dev/null 2>&1 || systemctl is-active --quiet rke2-server 2>/dev/null; then
    echo "server"
    return 0
  fi

  if systemctl list-unit-files rke2-agent.service >/dev/null 2>&1 || systemctl is-active --quiet rke2-agent 2>/dev/null; then
    echo "agent"
    return 0
  fi

  # If RKE2 is not installed yet, common is safer for pre-staging rules without
  # broadly opening server-only ports.
  echo "common"
}

add_k8s_rules() {
  local effective_role
  effective_role="$(resolve_node_role)"
  info "Effective Kubernetes/RKE2 node role: ${effective_role}"

  if [[ "$effective_role" == "none" ]]; then
    info "Skipping Kubernetes/RKE2 firewall allowances because node role is none."
    return 0
  fi

  local port
  for port in "${K8S_COMMON_TCP_PORTS[@]}"; do
    add_inbound_port_from_cidr "$DOMAIN_ZONE" "$K8S_SOURCE_CIDR" "$port" "tcp" "RKE2/Kubernetes common"
  done
  for port in "${K8S_COMMON_UDP_PORTS[@]}"; do
    add_inbound_port_from_cidr "$DOMAIN_ZONE" "$K8S_SOURCE_CIDR" "$port" "udp" "RKE2/Kubernetes common"
  done

  if [[ "$effective_role" == "server" ]]; then
    for port in "${K8S_SERVER_TCP_PORTS[@]}"; do
      add_inbound_port_from_cidr "$DOMAIN_ZONE" "$K8S_SOURCE_CIDR" "$port" "tcp" "RKE2 server"
    done
    for port in "${K8S_SERVER_UDP_PORTS[@]}"; do
      add_inbound_port_from_cidr "$DOMAIN_ZONE" "$K8S_SOURCE_CIDR" "$port" "udp" "RKE2 server"
    done
  fi

  if [[ "$OPEN_NODEPORTS" == "true" ]]; then
    warn "Opening Kubernetes NodePort range 30000-32767 from ${K8S_SOURCE_CIDR}. Only use this when the node must directly expose NodePorts."
    for port in "${NODEPORT_TCP_PORTS[@]}"; do
      add_inbound_port_from_cidr "$DOMAIN_ZONE" "$K8S_SOURCE_CIDR" "$port" "tcp" "Kubernetes NodePort"
    done
    for port in "${NODEPORT_UDP_PORTS[@]}"; do
      add_inbound_port_from_cidr "$DOMAIN_ZONE" "$K8S_SOURCE_CIDR" "$port" "udp" "Kubernetes NodePort"
    done
  fi
}

create_host_egress_policy() {
  local policy="$1"
  local egress_zone="$2"
  local dst_cidr="$3"
  local description="$4"

  info "Creating host egress policy ${policy}: HOST -> ${egress_zone}, allow destination ${dst_cidr}, drop everything else for that path."

  if [[ "$DRY_RUN" == "true" ]] || ! fw_policy_exists "$policy"; then
    run_cmd firewall-cmd --permanent --new-policy="$policy"
  fi

  run_cmd firewall-cmd --permanent --policy="$policy" --set-description="$description"
  run_cmd firewall-cmd --permanent --policy="$policy" --set-short="$policy"
  run_cmd firewall-cmd --permanent --policy="$policy" --add-ingress-zone=HOST
  run_cmd firewall-cmd --permanent --policy="$policy" --add-egress-zone="$egress_zone"
  run_cmd firewall-cmd --permanent --policy="$policy" --set-target=DROP
  run_cmd firewall-cmd --permanent --policy="$policy" --add-rich-rule="rule family=\"ipv4\" destination address=\"${dst_cidr}\" accept"
}

configure_firewalld() {
  info "Configuring firewalld zones."

  create_zone "$DOMAIN_ZONE" "$DOMAIN_IF" "Managed by ${SCRIPT_NAME}: domain/default-gateway zone bound to ${DOMAIN_IF}; default target DROP."
  create_zone "$STORAGE_ZONE" "$STORAGE_IF" "Managed by ${SCRIPT_NAME}: storage zone bound to ${STORAGE_IF}; default target DROP."
  create_zone "$ONPREM_ZONE" "$ONPREM_IF" "Managed by ${SCRIPT_NAME}: onprem zone bound to ${ONPREM_IF}; default target DROP."
  create_zone "$HYPERMUTE_ZONE" "$HYPERMUTE_IF" "Managed by ${SCRIPT_NAME}: hypermute zone bound to ${HYPERMUTE_IF}; default target DROP."

  info "Setting default firewalld zone to drop."
  run_cmd firewall-cmd --permanent --set-default-zone=drop

  info "Adding mandatory SSH allowance."
  add_inbound_port_from_cidr "$DOMAIN_ZONE" "$SSH_SOURCE_CIDR" "$SSH_PORT" "tcp" "SSH administration"

  add_k8s_rules

  info "Adding optional inbound application allowances."
  add_port_list_to_zone "$DOMAIN_ZONE" "$DOMAIN_CIDR" "tcp" "$ALLOW_DOMAIN_TCP" "custom domain TCP"
  add_port_list_to_zone "$DOMAIN_ZONE" "$DOMAIN_CIDR" "udp" "$ALLOW_DOMAIN_UDP" "custom domain UDP"
  add_port_list_to_zone "$STORAGE_ZONE" "$STORAGE_CIDR" "tcp" "$ALLOW_STORAGE_TCP" "custom storage TCP"
  add_port_list_to_zone "$STORAGE_ZONE" "$STORAGE_CIDR" "udp" "$ALLOW_STORAGE_UDP" "custom storage UDP"
  add_port_list_to_zone "$ONPREM_ZONE" "$ONPREM_CIDR" "tcp" "$ALLOW_ONPREM_TCP" "custom onprem TCP"
  add_port_list_to_zone "$ONPREM_ZONE" "$ONPREM_CIDR" "udp" "$ALLOW_ONPREM_UDP" "custom onprem UDP"
  add_port_list_to_zone "$HYPERMUTE_ZONE" "$HYPERMUTE_CIDR" "tcp" "$ALLOW_HYPERMUTE_TCP" "custom hypermute TCP"
  add_port_list_to_zone "$HYPERMUTE_ZONE" "$HYPERMUTE_CIDR" "udp" "$ALLOW_HYPERMUTE_UDP" "custom hypermute UDP"

  if [[ "$CREATE_HOST_EGRESS_POLICIES" == "true" ]]; then
    if firewalld_has_policy_support; then
      info "Creating HOST -> non-default zone egress policies."
      create_host_egress_policy "$HOST_TO_STORAGE_POLICY" "$STORAGE_ZONE" "$STORAGE_CIDR" "Managed by ${SCRIPT_NAME}: allow host egress to storage CIDR only over storage zone."
      create_host_egress_policy "$HOST_TO_ONPREM_POLICY" "$ONPREM_ZONE" "$ONPREM_CIDR" "Managed by ${SCRIPT_NAME}: allow host egress to onprem CIDR only over onprem zone."
      create_host_egress_policy "$HOST_TO_HYPERMUTE_POLICY" "$HYPERMUTE_ZONE" "$HYPERMUTE_CIDR" "Managed by ${SCRIPT_NAME}: allow host egress to hypermute CIDR only over hypermute zone."
    else
      warn "This firewalld version does not appear to support policy objects. Skipping HOST egress policies."
    fi
  else
    info "Skipping HOST egress policies because --no-host-egress-policies was specified."
  fi

  info "Reloading firewalld to apply permanent configuration."
  run_cmd firewall-cmd --reload
}

validate_result() {
  info "Validating final state."

  if [[ "$DRY_RUN" == "true" ]]; then
    info "Dry run complete. No system changes were made."
    return 0
  fi

  info "firewalld state:"
  firewall-cmd --state || true

  info "Active zones:"
  firewall-cmd --get-active-zones || true

  local zone
  for zone in "$DOMAIN_ZONE" "$STORAGE_ZONE" "$ONPREM_ZONE" "$HYPERMUTE_ZONE"; do
    info "Zone detail: ${zone}"
    firewall-cmd --zone="$zone" --list-all || true
  done

  if firewalld_has_policy_support; then
    info "Managed policies:"
    for policy in "$HOST_TO_STORAGE_POLICY" "$HOST_TO_ONPREM_POLICY" "$HOST_TO_HYPERMUTE_POLICY"; do
      if fw_policy_exists "$policy"; then
        firewall-cmd --policy="$policy" --list-all || true
      fi
    done
  fi

  info "Default route check:"
  ip route show default || true

  info "Forwarding sysctl check:"
  sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding || true

  info "Listening sockets. Review anything bound to 0.0.0.0 or ::: carefully."
  ss -lntup || true

  info "Validation completed."
}

print_summary() {
  cat <<SUMMARY

======================================================================
${SCRIPT_NAME} completed
======================================================================
Log file:
  ${LOG_FILE}
Latest log symlink:
  ${LATEST_LOG}

Managed zones:
  ${DOMAIN_ZONE}    -> ${DOMAIN_IF}    -> ${DOMAIN_CIDR}
  ${STORAGE_ZONE}   -> ${STORAGE_IF}   -> ${STORAGE_CIDR}
  ${ONPREM_ZONE}    -> ${ONPREM_IF}    -> ${ONPREM_CIDR}
  ${HYPERMUTE_ZONE} -> ${HYPERMUTE_IF} -> ${HYPERMUTE_CIDR}

Required management allowance:
  SSH tcp/${SSH_PORT} from ${SSH_SOURCE_CIDR} on ${DOMAIN_ZONE}/${DOMAIN_IF}

Kubernetes/RKE2:
  Requested node role: ${NODE_ROLE}
  Effective node role: $(resolve_node_role)
  K8s source CIDR: ${K8S_SOURCE_CIDR}
  NodePort range opened: ${OPEN_NODEPORTS}

Key follow-up checks:
  ip route show default
  firewall-cmd --get-active-zones
  firewall-cmd --zone=${DOMAIN_ZONE} --list-all
  firewall-cmd --zone=${STORAGE_ZONE} --list-all
  firewall-cmd --zone=${ONPREM_ZONE} --list-all
  firewall-cmd --zone=${HYPERMUTE_ZONE} --list-all
  sysctl net.ipv4.ip_forward
  ss -lntup

Operational warning:
  This script controls firewall policy. Validate on one non-critical node first,
  then roll out across the fleet with explicit --node-role server or agent.
======================================================================

SUMMARY
}

main() {
  require_root
  parse_args "$@"
  validate_config
  preflight
  install_and_start_firewalld
  disable_ufw_if_requested
  backup_firewalld_config
  write_sysctl_hardening
  reset_managed_firewalld_objects
  configure_firewalld
  validate_result
  print_summary
}

trap 'error "Script failed at line ${LINENO}. See ${LOG_FILE}"' ERR
main "$@"
