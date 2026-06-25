#!/usr/bin/env bash
# setup-ufw-zones.sh
#
# Purpose:
#   Configure UFW as interface-scoped firewall "zones" on a multi-NIC Ubuntu/Debian host.
#
# Zones:
#   restricted_zone: HTTPS inbound only
#   storage_zone:    NFS/iSCSI inbound only
#   domain_zone:     SSH, HTTP, HTTPS inbound; optional AD/DC/Samba domain-service inbound profile
#
# Security posture:
#   - Default deny inbound
#   - Default allow outbound
#   - Default deny routed/forwarded traffic
#   - Explicit deny route rules between assigned zone interfaces
#   - Kernel forwarding disabled
#   - Basic anti-spoofing and redirect/source-route hardening
#
# Notes:
#   UFW does not implement native zones like firewalld. This script emulates zones using
#   interface-scoped rules: "allow in on <interface> ...".
#
# Tested syntax target: Bash 4+, UFW 0.36+

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
BACKUP_ROOT="/root/ufw-zone-backups"
SYSCTL_DROPIN="/etc/sysctl.d/99-ufw-zone-hardening.conf"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: Run this script as root or with sudo." >&2
    exit 1
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: Required command not found: $cmd" >&2
    exit 1
  fi
}

trim() {
  local s="$*"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

yes_no() {
  local prompt="$1"
  local default="${2:-N}"
  local reply
  local suffix

  if [[ "$default" =~ ^[Yy]$ ]]; then
    suffix="[Y/n]"
  else
    suffix="[y/N]"
  fi

  while true; do
    read -r -p "$prompt $suffix: " reply
    reply="$(trim "$reply")"
    if [[ -z "$reply" ]]; then
      reply="$default"
    fi
    case "$reply" in
      y|Y|yes|YES|Yes) return 0 ;;
      n|N|no|NO|No) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

list_interfaces() {
  ip -o link show \
    | awk -F': ' '{print $2}' \
    | sed 's/@.*//' \
    | grep -Ev '^(lo|docker[0-9]*|br-|veth|virbr|zt|tailscale|wg|tun|tap)' \
    | sort -u
}

interface_exists() {
  local iface="$1"
  ip link show "$iface" >/dev/null 2>&1
}

print_interfaces() {
  echo
  echo "Detected physical/primary interfaces:"
  local i=1
  local iface
  while IFS= read -r iface; do
    [[ -z "$iface" ]] && continue
    local state mac addrs
    state="$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo unknown)"
    mac="$(cat "/sys/class/net/$iface/address" 2>/dev/null || echo unknown)"
    addrs="$(ip -o -4 addr show dev "$iface" 2>/dev/null | awk '{print $4}' | paste -sd ',' -)"
    [[ -z "$addrs" ]] && addrs="no-ipv4"
    printf '  %2d) %-18s state=%-8s mac=%-17s ipv4=%s\n' "$i" "$iface" "$state" "$mac" "$addrs"
    ((i++))
  done < <(list_interfaces)
  echo
}

read_iface_list() {
  local zone_name="$1"
  local prompt="$2"
  local input iface

  while true; do
    read -r -p "$prompt" input
    input="$(trim "$input")"
    if [[ -z "$input" ]]; then
      echo ""
      return 0
    fi

    local ok=1
    for iface in $input; do
      if ! interface_exists "$iface"; then
        echo "ERROR: Interface '$iface' does not exist. Try again."
        ok=0
      fi
    done

    if [[ "$ok" -eq 1 ]]; then
      echo "$input"
      return 0
    fi
  done
}

validate_no_overlap() {
  local all_ifaces=("$@")
  local seen=" "
  local iface
  for iface in "${all_ifaces[@]}"; do
    [[ -z "$iface" ]] && continue
    if [[ "$seen" == *" $iface "* ]]; then
      echo "ERROR: Interface '$iface' was assigned to more than one zone." >&2
      echo "Each NIC should belong to exactly one firewall zone for clean segmentation." >&2
      exit 1
    fi
    seen+="$iface "
  done
}

backup_current_config() {
  local ts backup_dir
  ts="$(date +%Y%m%d-%H%M%S)"
  backup_dir="$BACKUP_ROOT/$ts"
  mkdir -p "$backup_dir"

  echo "Creating backup in: $backup_dir"
  ufw status verbose > "$backup_dir/ufw-status-before.txt" 2>&1 || true
  ufw status numbered > "$backup_dir/ufw-status-numbered-before.txt" 2>&1 || true
  cp -a /etc/ufw "$backup_dir/etc-ufw" 2>/dev/null || true
  cp -a /etc/default/ufw "$backup_dir/default-ufw" 2>/dev/null || true
  cp -a "$SYSCTL_DROPIN" "$backup_dir/previous-$(basename "$SYSCTL_DROPIN")" 2>/dev/null || true

  echo "$backup_dir"
}

apply_sysctl_hardening() {
  cat > "$SYSCTL_DROPIN" <<'SYSCTL_EOF'
# Created by setup-ufw-zones.sh
# Multi-NIC firewall hardening. Keep the host from becoming a router between zones.

# Do not route traffic between interfaces/zones.
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Drop source-routed packets and ICMP redirects.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Do not send redirects; this host is not a router.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Spoofing hygiene. Loose mode is safer for multi-homed systems than strict mode.
# Set to 1 only when routing is simple/symmetric and you have validated it will not break traffic.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# Log spoofed/martian packets.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Avoid acting like a router on IPv6.
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
SYSCTL_EOF

  sysctl --system >/dev/null
}

configure_ufw_defaults() {
  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="DROP"/' /etc/default/ufw

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw default deny routed
  ufw logging medium
}

ufw_allow_in() {
  local iface="$1"
  local proto="$2"
  local port="$3"
  local comment="$4"
  shift 4
  local sources=("$@")

  if [[ "${#sources[@]}" -eq 0 ]]; then
    ufw allow in on "$iface" to any port "$port" proto "$proto" comment "$comment"
  else
    local src
    for src in "${sources[@]}"; do
      ufw allow in on "$iface" from "$src" to any port "$port" proto "$proto" comment "$comment from $src"
    done
  fi
}

parse_cidrs() {
  local input="$1"
  local cidrs=()
  local cidr
  input="$(trim "$input")"
  [[ -z "$input" ]] && return 0

  for cidr in $input; do
    if [[ "$cidr" == "any" ]]; then
      continue
    fi
    # Basic sanity check. UFW will do the final validation.
    if [[ ! "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ && ! "$cidr" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
      echo "ERROR: '$cidr' does not look like an IPv4/IPv6 address or CIDR." >&2
      exit 1
    fi
    cidrs+=("$cidr")
  done

  printf '%s\n' "${cidrs[@]}"
}

apply_restricted_zone() {
  local iface
  for iface in "$@"; do
    [[ -z "$iface" ]] && continue
    ufw_allow_in "$iface" tcp 443 "restricted_zone HTTPS"
  done
}

apply_storage_zone() {
  local sources_csv="$1"
  local include_nfs_udp="$2"
  local include_legacy_nfs="$3"
  shift 3

  local sources=()
  if [[ -n "$sources_csv" ]]; then
    mapfile -t sources < <(printf '%s\n' "$sources_csv" | sed '/^$/d')
  fi

  local iface
  for iface in "$@"; do
    [[ -z "$iface" ]] && continue

    # NFSv4 server default.
    ufw_allow_in "$iface" tcp 2049 "storage_zone NFSv4" "${sources[@]}"

    # Some environments still use NFS over UDP; keep this optional.
    if [[ "$include_nfs_udp" == "yes" ]]; then
      ufw_allow_in "$iface" udp 2049 "storage_zone NFS UDP" "${sources[@]}"
    fi

    # iSCSI target port.
    ufw_allow_in "$iface" tcp 3260 "storage_zone iSCSI target" "${sources[@]}"

    # Legacy NFSv3/rpcbind/mountd support. Use only if ports are pinned on the NFS server.
    if [[ "$include_legacy_nfs" == "yes" ]]; then
      for p in 111 20048 662 875 892 32765 32766 32767 32768; do
        ufw_allow_in "$iface" tcp "$p" "storage_zone legacy NFSv3 pinned port $p" "${sources[@]}"
        ufw_allow_in "$iface" udp "$p" "storage_zone legacy NFSv3 pinned port $p" "${sources[@]}"
      done
    fi
  done
}

apply_domain_zone() {
  local ssh_sources_csv="$1"
  local domain_profile="$2"
  shift 2

  local ssh_sources=()
  if [[ -n "$ssh_sources_csv" ]]; then
    mapfile -t ssh_sources < <(printf '%s\n' "$ssh_sources_csv" | sed '/^$/d')
  fi

  local iface
  for iface in "$@"; do
    [[ -z "$iface" ]] && continue

    # Admin/application inbound.
    ufw_allow_in "$iface" tcp 22 "domain_zone SSH" "${ssh_sources[@]}"
    ufw_allow_in "$iface" tcp 80 "domain_zone HTTP"
    ufw_allow_in "$iface" tcp 443 "domain_zone HTTPS"

    # Only expose AD/DC/Samba services if this host actually provides those services.
    if [[ "$domain_profile" == "dc" ]]; then
      # DNS
      ufw_allow_in "$iface" tcp 53 "domain_zone DNS TCP"
      ufw_allow_in "$iface" udp 53 "domain_zone DNS UDP"
      # Kerberos / kpasswd
      ufw_allow_in "$iface" tcp 88 "domain_zone Kerberos TCP"
      ufw_allow_in "$iface" udp 88 "domain_zone Kerberos UDP"
      ufw_allow_in "$iface" tcp 464 "domain_zone Kerberos password TCP"
      ufw_allow_in "$iface" udp 464 "domain_zone Kerberos password UDP"
      # LDAP / LDAPS
      ufw_allow_in "$iface" tcp 389 "domain_zone LDAP TCP"
      ufw_allow_in "$iface" udp 389 "domain_zone LDAP UDP"
      ufw_allow_in "$iface" tcp 636 "domain_zone LDAPS TCP"
      # SMB / RPC endpoint mapper
      ufw_allow_in "$iface" tcp 445 "domain_zone SMB"
      ufw_allow_in "$iface" tcp 135 "domain_zone RPC endpoint mapper"
      # Global Catalog
      ufw_allow_in "$iface" tcp 3268 "domain_zone Global Catalog"
      ufw_allow_in "$iface" tcp 3269 "domain_zone Global Catalog SSL"
      # NTP if the domain server is also authoritative time for clients.
      ufw_allow_in "$iface" udp 123 "domain_zone NTP"

      if yes_no "Add high dynamic RPC TCP range 49152:65535 for AD/DC compatibility? This is a wide range; only use on trusted internal domain networks." "N"; then
        ufw allow in on "$iface" proto tcp to any port 49152:65535 comment "domain_zone AD dynamic RPC high range"
      fi
    fi
  done
}

apply_interzone_route_denies() {
  local ifaces=("$@")
  local in_if out_if

  for in_if in "${ifaces[@]}"; do
    [[ -z "$in_if" ]] && continue
    for out_if in "${ifaces[@]}"; do
      [[ -z "$out_if" ]] && continue
      [[ "$in_if" == "$out_if" ]] && continue
      ufw route deny in on "$in_if" out on "$out_if" comment "deny routed traffic $in_if to $out_if"
    done
  done
}

show_summary() {
  local restricted="$1"
  local storage="$2"
  local domain="$3"
  local storage_sources="$4"
  local ssh_sources="$5"
  local domain_profile="$6"
  local nfs_udp="$7"
  local legacy_nfs="$8"

  echo
  echo "Planned firewall zone assignment:"
  printf '  restricted_zone: %s\n' "${restricted:-not assigned}"
  printf '  storage_zone:    %s\n' "${storage:-not assigned}"
  printf '  domain_zone:     %s\n' "${domain:-not assigned}"
  echo
  printf '  Storage allowed source CIDRs: %s\n' "${storage_sources:-any host reaching the storage NIC}"
  printf '  SSH allowed source CIDRs:     %s\n' "${ssh_sources:-any host reaching the domain NIC}"
  printf '  Domain profile:               %s\n' "$domain_profile"
  printf '  NFS UDP 2049:                 %s\n' "$nfs_udp"
  printf '  Legacy NFSv3 pinned ports:    %s\n' "$legacy_nfs"
  echo
  echo "This will reset existing UFW rules, then enable UFW. Existing UFW config will be backed up first."
  echo
}

main() {
  need_root
  need_cmd ip
  need_cmd ufw
  need_cmd sysctl
  need_cmd awk
  need_cmd sed

  echo "=== UFW Interface Zone Setup ==="
  echo "Host: $(hostname -f 2>/dev/null || hostname)"

  print_interfaces

  local restricted_input storage_input domain_input
  restricted_input="$(read_iface_list restricted_zone 'Enter interface(s) for restricted_zone [HTTPS inbound only], blank to skip: ')"
  storage_input="$(read_iface_list storage_zone 'Enter interface(s) for storage_zone [NFS/iSCSI only], blank to skip: ')"
  domain_input="$(read_iface_list domain_zone 'Enter interface(s) for domain_zone [SSH/HTTP/HTTPS + optional domain services], blank to skip: ')"

  local restricted_ifaces=($restricted_input)
  local storage_ifaces=($storage_input)
  local domain_ifaces=($domain_input)
  validate_no_overlap "${restricted_ifaces[@]}" "${storage_ifaces[@]}" "${domain_ifaces[@]}"

  if [[ ${#restricted_ifaces[@]} -eq 0 && ${#storage_ifaces[@]} -eq 0 && ${#domain_ifaces[@]} -eq 0 ]]; then
    echo "ERROR: No interfaces were assigned. Nothing to do." >&2
    exit 1
  fi

  echo
  echo "Storage-zone source restriction is strongly recommended."
  read -r -p "Enter storage peer CIDR(s), space-separated, or blank for any source on storage NIC: " storage_sources_raw
  local storage_sources
  storage_sources="$(parse_cidrs "$storage_sources_raw")"

  echo
  echo "SSH source restriction is strongly recommended."
  read -r -p "Enter trusted SSH source CIDR(s), space-separated, or blank for any source on domain NIC: " ssh_sources_raw
  local ssh_sources
  ssh_sources="$(parse_cidrs "$ssh_sources_raw")"

  local nfs_udp="no"
  local legacy_nfs="no"
  if [[ ${#storage_ifaces[@]} -gt 0 ]]; then
    if yes_no "Allow NFS UDP/2049 on storage_zone? TCP-only NFSv4 is the better baseline." "N"; then
      nfs_udp="yes"
    fi
    if yes_no "Add legacy NFSv3/rpcbind/mountd pinned ports on storage_zone? Only use if your NFS server is configured with fixed ports." "N"; then
      legacy_nfs="yes"
    fi
  fi

  local domain_profile="member"
  if [[ ${#domain_ifaces[@]} -gt 0 ]]; then
    if yes_no "Is this host acting as an AD Domain Controller or Samba AD DC and needs inbound domain-service ports?" "N"; then
      domain_profile="dc"
    fi
  fi

  show_summary "$restricted_input" "$storage_input" "$domain_input" "$storage_sources_raw" "$ssh_sources_raw" "$domain_profile" "$nfs_udp" "$legacy_nfs"

  if ! yes_no "Apply this firewall configuration now?" "N"; then
    echo "No changes applied."
    exit 0
  fi

  local backup_dir
  backup_dir="$(backup_current_config)"

  echo "Applying kernel/network hardening..."
  apply_sysctl_hardening

  echo "Configuring UFW defaults..."
  configure_ufw_defaults

  echo "Applying restricted_zone rules..."
  apply_restricted_zone "${restricted_ifaces[@]}"

  echo "Applying storage_zone rules..."
  apply_storage_zone "$storage_sources" "$nfs_udp" "$legacy_nfs" "${storage_ifaces[@]}"

  echo "Applying domain_zone rules..."
  apply_domain_zone "$ssh_sources" "$domain_profile" "${domain_ifaces[@]}"

  echo "Applying explicit inter-zone routed traffic denies..."
  local all_zone_ifaces=("${restricted_ifaces[@]}" "${storage_ifaces[@]}" "${domain_ifaces[@]}")
  apply_interzone_route_denies "${all_zone_ifaces[@]}"

  echo "Enabling UFW..."
  ufw --force enable

  echo
  echo "=== Final UFW status ==="
  ufw status verbose
  echo
  echo "Rule numbers:"
  ufw status numbered
  echo
  echo "Backup saved at: $backup_dir"
  echo "Done. Validate from each network before closing your admin session."
}

main "$@"
