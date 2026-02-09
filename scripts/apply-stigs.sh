#!/usr/bin/env bash
set -euo pipefail

# Apply firewall zone layout and RKE2 STIG checks with report-first workflow.
dry_run=false
apply_changes=false
report_only=false
assume_yes=false
non_interactive=false
run_kubectl_checks=false
restart_rke2=false
image_mode=false

show_help() {
  cat <<'EOF'
apply-stigs.sh - Report-first STIG helper for firewall and RKE2 host settings.

USAGE:
  ./scripts/apply-stigs.sh [options]

WORKFLOW:
  1) Collects firewall and RKE2 STIG-relevant checks.
  2) Prints a leadership-friendly compliance report.
  3) Prompts to apply remediations unless --apply or --report-only is used.
  4) Optionally prompts to run kubectl validations when RKE2 is running.

OPTIONS:
  --report-only        Report only; do not apply changes.
  --apply              Apply remediations without prompting.
  --dry-run, -n         Print commands without applying changes.
  --restart-rke2        Restart rke2-server or rke2-agent after config changes.
  --yes, -y             Auto-confirm prompts.
  --non-interactive     Fail if a prompt would be required.
  --image, -i           Golden image mode (apply + yes + non-interactive).
  --help, -h            Show this help.

EXAMPLES:
  ./scripts/apply-stigs.sh --report-only
  sudo ./scripts/apply-stigs.sh --apply
  sudo ./scripts/apply-stigs.sh --apply --restart-rke2
  sudo ./scripts/apply-stigs.sh --image

NOTES:
  - Run as root or with sudo available.
  - Pre-run RKE2 settings are applied even if RKE2 is not running.
  - Kubectl checks are optional and require cluster access.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      show_help
      exit 0
      ;;
    -n|--dry-run)
      dry_run=true
      shift
      ;;
    --apply)
      apply_changes=true
      shift
      ;;
    --report-only)
      report_only=true
      shift
      ;;
    -y|--yes)
      assume_yes=true
      shift
      ;;
    --non-interactive)
      non_interactive=true
      shift
      ;;
    --restart-rke2)
      restart_rke2=true
      shift
      ;;
    --image|-i)
      image_mode=true
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "$image_mode" == "true" ]]; then
  apply_changes=true
  assume_yes=true
  non_interactive=true
fi

run_cmd() {
  if [[ "$dry_run" == "true" ]]; then
    echo "DRY-RUN: $*"
  else
    "$@"
  fi
}

prompt_yes_no() {
  local prompt="$1"
  if [[ "$assume_yes" == "true" ]]; then
    return 0
  fi
  if [[ "$non_interactive" == "true" ]]; then
    echo "Non-interactive mode: prompt declined: $prompt" >&2
    return 1
  fi
  read -r -p "$prompt [y/N] " reply
  [[ "${reply,,}" == "y" || "${reply,,}" == "yes" ]]
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

install_ufw() {
  if command -v dnf >/dev/null 2>&1; then
    run_cmd $SUDO dnf install -y ufw
  elif command -v yum >/dev/null 2>&1; then
    run_cmd $SUDO yum install -y ufw
  elif command -v apt-get >/dev/null 2>&1; then
    run_cmd $SUDO apt-get update
    run_cmd $SUDO apt-get install -y ufw
  elif command -v zypper >/dev/null 2>&1; then
    run_cmd $SUDO zypper --non-interactive install ufw
  else
    echo "No supported package manager found to install ufw." >&2
    exit 1
  fi
}

check_command() {
  command -v "$1" >/dev/null 2>&1
}

add_result() {
  local id="$1"
  local title="$2"
  local status="$3"
  local details="$4"
  STIG_IDS+=("$id")
  STIG_TITLES+=("$title")
  STIG_STATUS+=("$status")
  STIG_DETAILS+=("$details")
}

print_report() {
  local total=${#STIG_IDS[@]}
  local pass=0 fail=0 manual=0 notrun=0 notapp=0
  local i
  for i in "${!STIG_STATUS[@]}"; do
    case "${STIG_STATUS[$i]}" in
      PASS) pass=$((pass + 1)) ;;
      FAIL) fail=$((fail + 1)) ;;
      MANUAL) manual=$((manual + 1)) ;;
      NOT-RUN) notrun=$((notrun + 1)) ;;
      NOT-APPLICABLE) notapp=$((notapp + 1)) ;;
    esac
  done

  echo ""
  echo "============================================================"
  echo "STIG COMPLIANCE REPORT"
  echo "Host: $(hostname)"
  echo "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "Totals: $total  PASS=$pass  FAIL=$fail  MANUAL=$manual  NOT-RUN=$notrun  N/A=$notapp"
  echo "============================================================"
  printf "%-24s | %-12s | %-64s\n" "ID" "STATUS" "TITLE"
  printf "%s\n" "-------------------------+--------------+------------------------------------------------------------------"
  for i in "${!STIG_IDS[@]}"; do
    printf "%-24s | %-12s | %-64.64s\n" "${STIG_IDS[$i]}" "${STIG_STATUS[$i]}" "${STIG_TITLES[$i]}"
    if [[ -n "${STIG_DETAILS[$i]}" ]]; then
      printf "  -> %s\n" "${STIG_DETAILS[$i]}"
    fi
  done
  echo "============================================================"
}

detect_rke2_role() {
  if systemctl list-unit-files | grep -q '^rke2-server\.service'; then
    echo "server"
    return
  fi
  if systemctl list-unit-files | grep -q '^rke2-agent\.service'; then
    echo "agent"
    return
  fi
  echo "none"
}

is_rke2_running() {
  if [[ "$RKE2_ROLE" == "server" ]]; then
    systemctl is-active --quiet rke2-server
  elif [[ "$RKE2_ROLE" == "agent" ]]; then
    systemctl is-active --quiet rke2-agent
  else
    return 1
  fi
}

ensure_yaml_list_item() {
  local file="$1"
  local key="$2"
  local value="$3"

  if [[ ! -f "$file" ]]; then
    printf "%s:\n  - \"%s\"\n" "$key" "$value" | run_cmd $SUDO tee "$file" >/dev/null
    return
  fi

  if grep -Fq "$value" "$file"; then
    return
  fi

  if grep -Eq "^${key}:" "$file"; then
    run_cmd $SUDO awk -v key="$key:" -v val="  - \"$value\"" '
      { print }
      $0 == key && !inserted { print val; inserted=1 }
    ' "$file" | run_cmd $SUDO tee "$file" >/dev/null
  else
    printf "\n%s:\n  - \"%s\"\n" "$key" "$value" | run_cmd $SUDO tee -a "$file" >/dev/null
  fi
}

config_has_value() {
  local file="$1"
  local value="$2"
  [[ -f "$file" ]] && grep -Fq "$value" "$file"
}

config_has_regex() {
  local file="$1"
  local pattern="$2"
  [[ -f "$file" ]] && grep -Eq "$pattern" "$file"
}

path_is_protected() {
  local target="$1"
  if [[ ! -e "$target" ]]; then
    return 1
  fi
  local mode
  mode=$(stat -c "%a" "$target" 2>/dev/null || true)
  if [[ -z "$mode" ]]; then
    return 1
  fi
  local group_write=$(( (mode / 10) % 10 ))
  local other_write=$(( mode % 10 ))
  if (( group_write >= 2 || other_write >= 2 )); then
    return 1
  fi
  return 0
}

check_interface() {
  local iface="$1"
  ip link show "$iface" >/dev/null 2>&1
}

ufw_is_active() {
  ufw status | grep -q 'Status: active'
}

firewall_report() {
  if ! check_command ufw; then
    echo "ufw not found" >&2
    return 1
  fi
  if ! ufw_is_active; then
    echo "ufw not active" >&2
    return 1
  fi
  return 0
}

apply_firewall() {
  if ! check_command ufw; then
    echo "ufw not found. Installing ufw..." >&2
    install_ufw
  fi

  if ! check_command ip; then
    echo "ip not found. Install iproute2 first." >&2
    exit 1
  fi

  local missing_iface=false
  if ! check_interface "ens33"; then
    echo "warning: interface ens33 not found" >&2
    missing_iface=true
  fi
  if ! check_interface "ens35"; then
    echo "warning: interface ens35 not found" >&2
    missing_iface=true
  fi
  if ! check_interface "ens36"; then
    echo "warning: interface ens36 not found" >&2
    missing_iface=true
  fi
  if [[ "$missing_iface" == "true" ]]; then
    echo "One or more interfaces are missing. Fix and re-run." >&2
    exit 1
  fi

  run_cmd $SUDO ufw default deny incoming
  run_cmd $SUDO ufw default deny outgoing
  run_cmd $SUDO ufw allow out on ens33
  run_cmd $SUDO ufw allow in on ens33 to any port 22 proto tcp
  run_cmd $SUDO ufw allow in on ens33 to any port 443 proto tcp
  run_cmd $SUDO ufw allow in on ens35 to any port 111 proto tcp
  run_cmd $SUDO ufw allow in on ens35 to any port 111 proto udp
  run_cmd $SUDO ufw allow in on ens35 to any port 2049 proto tcp
  run_cmd $SUDO ufw allow in on ens35 to any port 2049 proto udp
  run_cmd $SUDO ufw allow in on ens36 to any port 443 proto tcp

  run_cmd $SUDO ufw route deny in on ens33 out on ens35
  run_cmd $SUDO ufw route deny in on ens33 out on ens36
  run_cmd $SUDO ufw route deny in on ens35 out on ens33
  run_cmd $SUDO ufw route deny in on ens35 out on ens36
  run_cmd $SUDO ufw route deny in on ens36 out on ens33
  run_cmd $SUDO ufw route deny in on ens36 out on ens35

  if ! ufw_is_active; then
    run_cmd $SUDO ufw --force enable
  fi

  if is_rke2_running; then
    if [[ "$RKE2_ROLE" == "server" ]]; then
      run_cmd $SUDO ufw allow in on ens33 to any port 6443 proto tcp
      run_cmd $SUDO ufw allow in on ens33 to any port 9345 proto tcp
      run_cmd $SUDO ufw allow in on ens33 to any port 10250 proto tcp
      run_cmd $SUDO ufw allow in on ens33 to any port 8472 proto udp
    elif [[ "$RKE2_ROLE" == "agent" ]]; then
      run_cmd $SUDO ufw allow in on ens33 to any port 10250 proto tcp
      run_cmd $SUDO ufw allow in on ens33 to any port 8472 proto udp
    fi
  fi
}

apply_rke2_config() {
  local file="/etc/rancher/rke2/config.yaml"

  if [[ "$RKE2_ROLE" == "server" ]]; then
    ensure_yaml_list_item "$file" "kube-controller-manager-arg" "tls-min-version=VersionTLS12"
    ensure_yaml_list_item "$file" "kube-controller-manager-arg" "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    ensure_yaml_list_item "$file" "kube-controller-manager-arg" "use-service-account-credentials=true"
    ensure_yaml_list_item "$file" "kube-controller-manager-arg" "bind-address=127.0.0.1"

    ensure_yaml_list_item "$file" "kube-scheduler-arg" "tls-min-version=VersionTLS12"
    ensure_yaml_list_item "$file" "kube-scheduler-arg" "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    ensure_yaml_list_item "$file" "kube-scheduler-arg" "bind-address=127.0.0.1"

    ensure_yaml_list_item "$file" "kube-apiserver-arg" "tls-min-version=VersionTLS12"
    ensure_yaml_list_item "$file" "kube-apiserver-arg" "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    ensure_yaml_list_item "$file" "kube-apiserver-arg" "anonymous-auth=false"
  fi

  if [[ "$RKE2_ROLE" == "server" || "$RKE2_ROLE" == "agent" ]]; then
    ensure_yaml_list_item "$file" "kubelet-arg" "anonymous-auth=false"
    ensure_yaml_list_item "$file" "kubelet-arg" "read-only-port=0"
    ensure_yaml_list_item "$file" "kubelet-arg" "authorization-mode=Webhook"
  fi

  run_cmd $SUDO chown root:root "$file"
  run_cmd $SUDO chmod 600 "$file"
}

report_firewall_controls() {
  if ! check_command ufw; then
    add_result "HOST-FW" "Host firewall installed and active" "FAIL" "ufw not found"
    return
  fi
  if ! ufw_is_active; then
    add_result "HOST-FW" "Host firewall installed and active" "FAIL" "ufw not active"
    return
  fi
  add_result "HOST-FW" "Host firewall installed and active" "PASS" "ufw active"
}

report_rke2_controls() {
  local config="/etc/rancher/rke2/config.yaml"
  local config_exists=false
  if [[ -f "$config" ]]; then
    config_exists=true
  fi

  if [[ "$RKE2_ROLE" == "none" ]]; then
    add_result "RKE2" "RKE2 role detected" "NOT-APPLICABLE" "rke2-server/agent not detected"
    add_result "RKE2-RUNNING" "RKE2 service running" "NOT-APPLICABLE" "rke2 service not installed"
    if [[ "$config_exists" == "true" ]]; then
      add_result "RKE2-CONFIG" "RKE2 config present" "PASS" "${config}"
    else
      add_result "RKE2-CONFIG" "RKE2 config present" "NOT-RUN" "config not found; can be created before install"
    fi
    add_result "SV-254553r1016525_rule" "TLS settings (server-only)" "NOT-RUN" "role unknown before install"
    add_result "SV-254554r1043176_rule" "Controller manager credentials (server-only)" "NOT-RUN" "role unknown before install"
    add_result "SV-254556r1137638_rule" "Controller manager secure binding (server-only)" "NOT-RUN" "role unknown before install"
    add_result "SV-254562r1137640_rule" "API server anonymous auth disabled (server-only)" "NOT-RUN" "role unknown before install"
    add_result "SV-254563r960906_rule" "Audit policy configured (server-only)" "NOT-RUN" "role unknown before install"

    if config_has_value "$config" "anonymous-auth=false"; then
      add_result "SV-254557r1137638_rule" "Kubelet anonymous auth disabled" "PASS" "anonymous-auth=false"
    else
      add_result "SV-254557r1137638_rule" "Kubelet anonymous auth disabled" "NOT-RUN" "config not set before install"
    fi

    if config_has_value "$config" "read-only-port=0"; then
      add_result "SV-254559r1137639_rule" "Kubelet read-only port disabled" "PASS" "read-only-port=0"
    else
      add_result "SV-254559r1137639_rule" "Kubelet read-only port disabled" "NOT-RUN" "config not set before install"
    fi

    if config_has_value "$config" "authorization-mode=Webhook"; then
      add_result "SV-254561r1137639_rule" "Kubelet explicit authorization" "PASS" "authorization-mode=Webhook"
    else
      add_result "SV-254561r1137639_rule" "Kubelet explicit authorization" "NOT-RUN" "config not set before install"
    fi

    if [[ "$config_exists" == "true" ]]; then
      local perms
      perms=$(stat -c "%a %U %G" "$config" 2>/dev/null || true)
      if [[ "$perms" == "600 root root" ]]; then
        add_result "SV-254564r1156618_rule" "RKE2 config protected" "PASS" "permissions $perms"
      else
        add_result "SV-254564r1156618_rule" "RKE2 config protected" "FAIL" "permissions $perms"
      fi
    else
      add_result "SV-254564r1156618_rule" "RKE2 config protected" "NOT-RUN" "config not found"
    fi

    if path_is_protected "/etc/rancher/rke2"; then
      add_result "SV-254564r1156618_rule" "RKE2 config directory protected" "PASS" "/etc/rancher/rke2"
    else
      add_result "SV-254564r1156618_rule" "RKE2 config directory protected" "NOT-RUN" "/etc/rancher/rke2 missing"
    fi

    if path_is_protected "/var/lib/rancher/rke2"; then
      add_result "SV-254564r1156618_rule" "RKE2 data directory protected" "PASS" "/var/lib/rancher/rke2"
    else
      add_result "SV-254564r1156618_rule" "RKE2 data directory protected" "NOT-RUN" "/var/lib/rancher/rke2 missing"
    fi

    add_result "SV-254555r1056186_rule" "RKE2 components configured per guidance" "MANUAL" "verify against site guidance"
    add_result "SV-254565r960963_rule" "Only essential configurations" "MANUAL" "review config for extra flags"
    add_result "SV-254568r1016534_rule" "Session termination enforced" "MANUAL" "review timeouts"
    add_result "SV-254569r1016537_rule" "Security functions isolated" "MANUAL" "review runtime isolation"
    add_result "SV-254571r1156616_rule" "Prevent nonprivileged privileged functions" "MANUAL" "review RBAC and policy"
    add_result "SV-254572r1016560_rule" "Privileged updates/images restricted" "MANUAL" "review admission policy"
    add_result "SV-268321r1017019_rule" "RKE2 built from verified packages" "MANUAL" "verify carbide/hauler provenance"
    add_result "SV-254566r1173952_rule" "PPSM CAL ports/protocols" "NOT-RUN" "kubectl checks skipped"
    add_result "SV-254567r1016559_rule" "Cryptographic password storage" "NOT-RUN" "kubectl checks skipped"
    add_result "SV-254570r1137645_rule" "Separate execution domains" "NOT-RUN" "kubectl checks skipped"
    add_result "SV-254574r961677_rule" "Remove old components" "NOT-RUN" "kubectl checks skipped"
    add_result "SV-254575r1137649_rule" "Latest authorized images" "NOT-RUN" "kubectl checks skipped"
    return
  fi

  add_result "RKE2" "RKE2 role detected" "PASS" "role: $RKE2_ROLE"
  if is_rke2_running; then
    add_result "RKE2-RUNNING" "RKE2 service running" "PASS" "service active"
  else
    add_result "RKE2-RUNNING" "RKE2 service running" "FAIL" "service inactive"
  fi

  if [[ "$RKE2_ROLE" == "server" ]]; then
    if config_has_regex "$config" 'tls-min-version=VersionTLS1[2-3]'; then
      add_result "SV-254553r1016525_rule" "TLS min version set to 1.2+" "PASS" "tls-min-version found"
    else
      add_result "SV-254553r1016525_rule" "TLS min version set to 1.2+" "FAIL" "missing tls-min-version"
    fi

    if config_has_value "$config" "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" \
      && config_has_value "$config" "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" \
      && config_has_value "$config" "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305" \
      && config_has_value "$config" "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" \
      && config_has_value "$config" "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305" \
      && config_has_value "$config" "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"; then
      add_result "SV-254553r1016525_rule" "TLS cipher suites configured" "PASS" "cipher suites present"
    else
      add_result "SV-254553r1016525_rule" "TLS cipher suites configured" "FAIL" "missing cipher suites"
    fi

    if config_has_value "$config" "use-service-account-credentials=true"; then
      add_result "SV-254554r1043176_rule" "Controller manager uses service account credentials" "PASS" "use-service-account-credentials set"
    else
      add_result "SV-254554r1043176_rule" "Controller manager uses service account credentials" "FAIL" "missing use-service-account-credentials"
    fi

    if config_has_value "$config" "bind-address=127.0.0.1"; then
      add_result "SV-254556r1137638_rule" "Controller manager secure binding" "PASS" "bind-address set"
    else
      add_result "SV-254556r1137638_rule" "Controller manager secure binding" "FAIL" "missing bind-address"
    fi

    if config_has_value "$config" "anonymous-auth=false"; then
      add_result "SV-254562r1137640_rule" "API server anonymous auth disabled" "PASS" "anonymous-auth=false"
    else
      add_result "SV-254562r1137640_rule" "API server anonymous auth disabled" "FAIL" "missing anonymous-auth=false"
    fi

    if config_has_regex "$config" "audit-policy-file=" || config_has_regex "$config" "audit-log-path="; then
      add_result "SV-254563r960906_rule" "Audit policy configured" "PASS" "audit configuration present"
    else
      add_result "SV-254563r960906_rule" "Audit policy configured" "FAIL" "missing audit-policy-file or audit-log-path"
    fi
  else
    add_result "SV-254553r1016525_rule" "TLS settings (server-only)" "NOT-APPLICABLE" "agent role"
    add_result "SV-254554r1043176_rule" "Controller manager credentials (server-only)" "NOT-APPLICABLE" "agent role"
    add_result "SV-254556r1137638_rule" "Controller manager secure binding (server-only)" "NOT-APPLICABLE" "agent role"
    add_result "SV-254562r1137640_rule" "API server anonymous auth disabled (server-only)" "NOT-APPLICABLE" "agent role"
    add_result "SV-254563r960906_rule" "Audit policy configured (server-only)" "NOT-APPLICABLE" "agent role"
  fi

  if config_has_value "$config" "anonymous-auth=false"; then
    add_result "SV-254557r1137638_rule" "Kubelet anonymous auth disabled" "PASS" "anonymous-auth=false"
  else
    add_result "SV-254557r1137638_rule" "Kubelet anonymous auth disabled" "FAIL" "missing anonymous-auth=false"
  fi

  if config_has_value "$config" "read-only-port=0"; then
    add_result "SV-254559r1137639_rule" "Kubelet read-only port disabled" "PASS" "read-only-port=0"
  else
    add_result "SV-254559r1137639_rule" "Kubelet read-only port disabled" "FAIL" "missing read-only-port=0"
  fi

  if config_has_value "$config" "authorization-mode=Webhook"; then
    add_result "SV-254561r1137639_rule" "Kubelet explicit authorization" "PASS" "authorization-mode=Webhook"
  else
    add_result "SV-254561r1137639_rule" "Kubelet explicit authorization" "FAIL" "missing authorization-mode=Webhook"
  fi

  if [[ -f "$config" ]]; then
    local perms
    perms=$(stat -c "%a %U %G" "$config" 2>/dev/null || true)
    if [[ "$perms" == "600 root root" ]]; then
      add_result "SV-254564r1156618_rule" "RKE2 config protected" "PASS" "permissions $perms"
    else
      add_result "SV-254564r1156618_rule" "RKE2 config protected" "FAIL" "permissions $perms"
    fi
  else
    add_result "SV-254564r1156618_rule" "RKE2 config protected" "FAIL" "config not found"
  fi

  if path_is_protected "/etc/rancher/rke2"; then
    add_result "SV-254564r1156618_rule" "RKE2 config directory protected" "PASS" "/etc/rancher/rke2"
  else
    add_result "SV-254564r1156618_rule" "RKE2 config directory protected" "FAIL" "/etc/rancher/rke2"
  fi

  if path_is_protected "/var/lib/rancher/rke2"; then
    add_result "SV-254564r1156618_rule" "RKE2 data directory protected" "PASS" "/var/lib/rancher/rke2"
  else
    add_result "SV-254564r1156618_rule" "RKE2 data directory protected" "FAIL" "/var/lib/rancher/rke2"
  fi

  add_result "SV-254555r1056186_rule" "RKE2 components configured per guidance" "MANUAL" "verify against site guidance"
  add_result "SV-254565r960963_rule" "Only essential configurations" "MANUAL" "review config for extra flags"
  add_result "SV-254568r1016534_rule" "Session termination enforced" "MANUAL" "review timeouts"
  add_result "SV-254569r1016537_rule" "Security functions isolated" "MANUAL" "review runtime isolation"
  add_result "SV-254571r1156616_rule" "Prevent nonprivileged privileged functions" "MANUAL" "review RBAC and policy"
  add_result "SV-254572r1016560_rule" "Privileged updates/images restricted" "MANUAL" "review admission policy"
  add_result "SV-268321r1017019_rule" "RKE2 built from verified packages" "MANUAL" "verify carbide/hauler provenance"

  if [[ "$run_kubectl_checks" == "true" ]]; then
    if check_command kubectl; then
      if kubectl version --short >/dev/null 2>&1; then
        add_result "KUBECTL" "kubectl access" "PASS" "kubectl version OK"
      else
        add_result "KUBECTL" "kubectl access" "FAIL" "kubectl unable to reach cluster"
      fi
    else
      add_result "KUBECTL" "kubectl access" "FAIL" "kubectl not found"
    fi

    add_result "SV-254566r1173952_rule" "PPSM CAL ports/protocols" "MANUAL" "requires cluster review"
    add_result "SV-254567r1016559_rule" "Cryptographic password storage" "MANUAL" "requires cluster review"
    add_result "SV-254570r1137645_rule" "Separate execution domains" "MANUAL" "requires cluster review"
    add_result "SV-254574r961677_rule" "Remove old components" "MANUAL" "requires cluster review"
    add_result "SV-254575r1137649_rule" "Latest authorized images" "MANUAL" "requires cluster review"
  else
    add_result "SV-254566r1173952_rule" "PPSM CAL ports/protocols" "NOT-RUN" "kubectl checks skipped"
    add_result "SV-254567r1016559_rule" "Cryptographic password storage" "NOT-RUN" "kubectl checks skipped"
    add_result "SV-254570r1137645_rule" "Separate execution domains" "NOT-RUN" "kubectl checks skipped"
    add_result "SV-254574r961677_rule" "Remove old components" "NOT-RUN" "kubectl checks skipped"
    add_result "SV-254575r1137649_rule" "Latest authorized images" "NOT-RUN" "kubectl checks skipped"
  fi
}

STIG_IDS=()
STIG_TITLES=()
STIG_STATUS=()
STIG_DETAILS=()

RKE2_ROLE=$(detect_rke2_role)

if [[ "$RKE2_ROLE" != "none" ]] && is_rke2_running; then
  if prompt_yes_no "Run kubectl validation checks?"; then
    run_kubectl_checks=true
  fi
fi

report_firewall_controls
report_rke2_controls
print_report

if [[ "$report_only" == "true" ]]; then
  exit 0
fi

if [[ "$apply_changes" == "false" ]]; then
  if ! prompt_yes_no "Apply remediations now?"; then
    exit 0
  fi
fi

apply_firewall
if [[ "$RKE2_ROLE" != "none" || -f "/etc/rancher/rke2/config.yaml" || -d "/etc/rancher/rke2" ]]; then
  apply_rke2_config
  if [[ "$restart_rke2" == "true" ]]; then
    if [[ "$RKE2_ROLE" == "server" ]]; then
      if systemctl is-active --quiet rke2-server; then
        run_cmd $SUDO systemctl restart rke2-server
      else
        run_cmd $SUDO systemctl start rke2-server
      fi
    elif [[ "$RKE2_ROLE" == "agent" ]]; then
      if systemctl is-active --quiet rke2-agent; then
        run_cmd $SUDO systemctl restart rke2-agent
      else
        run_cmd $SUDO systemctl start rke2-agent
      fi
    fi
  else
    echo "RKE2 configuration updated. Restart rke2-server/rke2-agent if required." >&2
  fi
fi

if [[ "$dry_run" == "true" ]]; then
  echo "Dry-run complete. No changes applied."
else
  echo "Changes applied."
fi

if firewall_report; then
  echo ""
  echo "Firewall status:"
  ufw status verbose
else
  echo ""
  echo "warning: ufw is not running; skipping report" >&2
fi
