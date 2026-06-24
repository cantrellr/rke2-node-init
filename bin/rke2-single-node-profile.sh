#!/usr/bin/env bash
#
# Apply, render, verify, or execute a production-style single-node RKE2 profile
# overlay for rkeprep/v2 manifests.
#
# This helper owns the explicit single-node kind flow:
#   kind: singleNodeImage  -> delegate to bin/rke2nodeinit.sh image
#   kind: singleNodeServer -> apply the single-node overlay, then delegate to
#                             bin/rke2nodeinit.sh server
#
# The existing golden-image, registry, network, and base server workflows stay in
# bin/rke2nodeinit.sh. This script only adds the single-node contract, RKE2
# config.yaml.d overlay, and low-resource packaged-component manifests.

set -Eeuo pipefail
trap 'rc=$?; echo "[ERROR] ${BASH_SOURCE[0]} failed at line ${LINENO} with exit ${rc}" >&2; exit ${rc}' ERR
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

ACTION=""
CONFIG_FILE=""
YAML_KIND=""
PROFILE_MODE="production"
OUTPUT_DIR="/etc/rancher/rke2/config.yaml.d"
MANIFEST_DIR="/var/lib/rancher/rke2/server/manifests"
DRY_RUN=0
ENABLE_CIS=1
ENABLE_LOW_RESOURCE_MANIFESTS=1
ENABLE_DEFAULT_NETWORK_POLICY=1
ENABLE_INGRESS=0
FORCE=0
declare -a NODEINIT_ARGS=()
declare -A YAML_VALUES=()
YAML_CACHE_FILE=""

usage() {
  cat <<'USAGE'
Usage:
  sudo bin/rke2-single-node-profile.sh -f <rkeprep-yaml> [options]
  sudo bin/rke2-single-node-profile.sh image  -f <rkeprep-yaml> [options]
  sudo bin/rke2-single-node-profile.sh server -f <rkeprep-yaml> [options]
       bin/rke2-single-node-profile.sh render -f <rkeprep-yaml> [options]
  sudo bin/rke2-single-node-profile.sh apply  -f <rkeprep-yaml> [options]
  sudo bin/rke2-single-node-profile.sh verify [options]

rkeprep/v2 single-node kinds:
  kind: singleNodeImage   Prepare the single-node golden image by delegating to
                          bin/rke2nodeinit.sh image -f <rkeprep-yaml> ...
  kind: singleNodeServer  Apply the single-node overlay, then delegate to
                          bin/rke2nodeinit.sh server -f <rkeprep-yaml> ...

Actions:
  image     Execute the single-node image process. This intentionally reuses
            the existing rke2nodeinit image action.
  server    Apply the single-node overlay, then execute the existing
            rke2nodeinit server action.
  apply     Write /etc/rancher/rke2/config.yaml.d/20-single-node-production.yaml
            and packaged-component HelmChartConfig manifests.
  render    Print the RKE2 single-node overlay to stdout without writing files.
  verify    Inspect the generated overlay/manifests and report what is present.

Options:
  -f, --file FILE              rkeprep/v2 YAML manifest.
  --mode production|dev        Profile mode. production is default.
  --output-dir DIR             RKE2 config drop-in directory.
                               Default: /etc/rancher/rke2/config.yaml.d
  --manifest-dir DIR           RKE2 auto-deploy manifest directory.
                               Default: /var/lib/rancher/rke2/server/manifests
  --dry-run                    Show intended writes without touching disk. With
                               image/server, also passes --dry-run to
                               bin/rke2nodeinit.sh.
  --no-cis                     Do not set profile: cis in the overlay.
  --no-low-resource-manifests  Do not write HelmChartConfig manifests.
  --enable-ingress             Do not force ingress-controller: none.
  --disable-default-netpol     Do not write a default namespace deny policy.
  --force                      Run overlay actions even when YAML does not
                               explicitly opt in.
  -y, --yes                    Passed through to bin/rke2nodeinit.sh.
  --                           Pass remaining arguments through to
                               bin/rke2nodeinit.sh when using image/server.
  -h, --help                   Show this help.

YAML opt-in keys honored when present:
  spec.clusterMode: single-node
  spec.singleNode.enabled: true
  spec.singleNode.mode: production|dev
  spec.singleNode.enableCIS: true|false
  spec.singleNode.lowResourceAddons: true|false
  spec.singleNode.defaultNetworkPolicy: true|false
  spec.singleNode.ingressController: none|traefik|ingress-nginx
  spec.singleNode.snapshotScheduleCron: "0 */6 * * *"
  spec.singleNode.snapshotRetention: 12
  spec.singleNode.snapshotDir: /var/lib/rancher/rke2/server/db/snapshots
  spec.singleNode.auditLogMaxAge: 30
  spec.singleNode.auditLogMaxBackup: 10
  spec.singleNode.auditLogMaxSize: 100

Recommended kind-driven flow:
  sudo bash bin/rke2-single-node-profile.sh -f configs/single-node/golden-image.yaml -y
  sudo bash bin/rke2-single-node-profile.sh -f configs/single-node/production-server.yaml -y

Equivalent explicit-action flow:
  sudo bash bin/rke2-single-node-profile.sh image -f configs/single-node/golden-image.yaml -y
  sudo bash bin/rke2-single-node-profile.sh server -f configs/single-node/production-server.yaml -y
USAGE
}

log() { printf '[%s] %s\n' "$1" "$2" >&2; }
info() { log INFO "$*"; }
warn() { log WARN "$*"; }
fatal() { log ERROR "$*"; exit 1; }

bool_true() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|y|on|enabled) return 0 ;;
    *) return 1 ;;
  esac
}

bool_false() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    0|false|no|n|off|disabled) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_kind() {
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]_-'
}

load_yaml_cache() {
  [[ -n "${CONFIG_FILE}" && -f "${CONFIG_FILE}" ]] || return 0
  [[ "${YAML_CACHE_FILE}" == "${CONFIG_FILE}" ]] && return 0

  YAML_VALUES=()
  while IFS=$'\t' read -r key value; do
    [[ -n "${key}" ]] || continue
    YAML_VALUES["${key}"]="${value}"
  done < <(python3 - "${CONFIG_FILE}" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text(encoding='utf-8').splitlines()
stack = []
scalar = re.compile(r'^(?P<indent>\s*)(?P<key>[A-Za-z0-9_.-]+)\s*:\s*(?P<value>.*?)\s*$')
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
    if value:
        value = value.strip('"\'')
        print('.'.join(current) + '\t' + value)
    else:
        stack.append((indent, key))
PY
  )
  YAML_CACHE_FILE="${CONFIG_FILE}"
}

yaml_scalar() {
  local file="$1" dotted="$2"
  [[ -f "$file" ]] || return 1
  load_yaml_cache
  if [[ -n "${YAML_VALUES[$dotted]+set}" ]]; then
    printf '%s\n' "${YAML_VALUES[$dotted]}"
    return 0
  fi
  return 1
}

first_yaml_scalar() {
  local file="$1"; shift
  local key value
  for key in "$@"; do
    value="$(yaml_scalar "$file" "$key" || true)"
    if [[ -n "$value" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  done
  return 1
}

parse_args() {
  if [[ $# -gt 0 && "$1" != -* ]]; then
    ACTION="$1"
    shift
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f|--file) CONFIG_FILE="${2:-}"; shift 2 ;;
      --mode) PROFILE_MODE="${2:-production}"; shift 2 ;;
      --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
      --manifest-dir) MANIFEST_DIR="${2:-}"; shift 2 ;;
      --dry-run) DRY_RUN=1; NODEINIT_ARGS+=("--dry-run"); shift ;;
      --no-cis) ENABLE_CIS=0; shift ;;
      --no-low-resource-manifests) ENABLE_LOW_RESOURCE_MANIFESTS=0; shift ;;
      --enable-ingress) ENABLE_INGRESS=1; shift ;;
      --disable-default-netpol) ENABLE_DEFAULT_NETWORK_POLICY=0; shift ;;
      --force) FORCE=1; shift ;;
      -y|--yes) NODEINIT_ARGS+=("-y"); shift ;;
      -v|-r|-u|-p|-n|--boot-yaml-path|--boot-mode|--vm-platform)
        [[ -n "${2:-}" ]] || fatal "$1 requires an argument"
        NODEINIT_ARGS+=("$1" "$2")
        shift 2
        ;;
      --boot-yaml-path=*|--boot-mode=*|--vm-platform=*) NODEINIT_ARGS+=("$1"); shift ;;
      -P|--apply-netplan-now|--load-images|--verify-layers|--verbose|--quiet|--enable-boot-service|--fix-cni-permissions|--enable-fips)
        NODEINIT_ARGS+=("$1"); shift ;;
      --)
        shift
        NODEINIT_ARGS+=("$@")
        break
        ;;
      -h|--help) usage; exit 0 ;;
      *) fatal "Unknown argument: $1" ;;
    esac
  done

  case "${PROFILE_MODE}" in production|dev) ;; *) fatal "--mode must be production or dev" ;; esac
}

load_yaml_metadata() {
  [[ -n "${CONFIG_FILE}" ]] || return 0
  [[ -f "${CONFIG_FILE}" ]] || fatal "Config file not found: ${CONFIG_FILE}"

  if [[ "${CONFIG_FILE}" != /* ]]; then
    CONFIG_FILE="$(cd -- "$(dirname -- "${CONFIG_FILE}")" && pwd -P)/$(basename -- "${CONFIG_FILE}")"
  fi

  load_yaml_cache

  local api
  api="$(first_yaml_scalar "${CONFIG_FILE}" apiVersion || true)"
  [[ "${api}" == "rkeprep/v2" ]] || fatal "Unsupported apiVersion: '${api:-<none>}' (expected rkeprep/v2)"

  YAML_KIND="$(first_yaml_scalar "${CONFIG_FILE}" kind || true)"
  [[ -n "${YAML_KIND}" ]] || fatal "Missing YAML kind in ${CONFIG_FILE}"
}

derive_action_from_kind() {
  [[ -n "${CONFIG_FILE}" ]] || return 0
  [[ -z "${ACTION}" ]] || return 0

  case "$(normalize_kind "${YAML_KIND}")" in
    singlenodeimage) ACTION="image" ;;
    singlenodeserver) ACTION="server" ;;
    image)
      if is_single_node_image_hint; then ACTION="image"; else fatal "kind: Image is not an explicit single-node kind. Use kind: singleNodeImage for this helper."; fi
      ;;
    server)
      if is_single_node_enabled; then ACTION="server"; else fatal "kind: Server is not an explicit single-node kind and is not opted into single-node mode."; fi
      ;;
    *) fatal "Unsupported YAML kind for single-node helper: '${YAML_KIND}'" ;;
  esac
}

validate_action() {
  case "${ACTION:-}" in image|server|apply|render|verify) ;; *) fatal "Unsupported or missing action: ${ACTION:-<none>}" ;; esac
}

load_yaml_overrides() {
  [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]] || return 0

  local value
  value="$(first_yaml_scalar "$CONFIG_FILE" spec.singleNode.mode spec.single-node.mode || true)"
  [[ -n "$value" ]] && PROFILE_MODE="$value"

  value="$(first_yaml_scalar "$CONFIG_FILE" spec.singleNode.enableCIS spec.single-node.enable-cis || true)"
  if [[ -n "$value" ]]; then
    bool_true "$value" && ENABLE_CIS=1
    bool_false "$value" && ENABLE_CIS=0
  fi

  value="$(first_yaml_scalar "$CONFIG_FILE" spec.singleNode.lowResourceAddons spec.single-node.low-resource-addons || true)"
  if [[ -n "$value" ]]; then
    bool_true "$value" && ENABLE_LOW_RESOURCE_MANIFESTS=1
    bool_false "$value" && ENABLE_LOW_RESOURCE_MANIFESTS=0
  fi

  value="$(first_yaml_scalar "$CONFIG_FILE" spec.singleNode.defaultNetworkPolicy spec.single-node.default-network-policy || true)"
  if [[ -n "$value" ]]; then
    bool_true "$value" && ENABLE_DEFAULT_NETWORK_POLICY=1
    bool_false "$value" && ENABLE_DEFAULT_NETWORK_POLICY=0
  fi

  value="$(first_yaml_scalar "$CONFIG_FILE" spec.singleNode.ingressController spec.ingress-controller spec.ingressController || true)"
  if [[ -n "$value" && "$value" != "none" ]]; then
    ENABLE_INGRESS=1
  fi
}

is_single_node_image_hint() {
  [[ "$FORCE" -eq 1 ]] && return 0
  [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]] || return 1
  local value
  value="$(first_yaml_scalar "$CONFIG_FILE" spec.clusterMode spec.cluster-mode || true)"
  [[ "$value" == "single-node" || "$value" == "singleNode" || "$value" == "single" ]] && return 0
  value="$(first_yaml_scalar "$CONFIG_FILE" spec.singleNodeImage spec.single-node-image || true)"
  bool_true "$value" && return 0
  return 1
}

is_single_node_enabled() {
  [[ "$FORCE" -eq 1 ]] && return 0
  [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]] || return 1

  case "$(normalize_kind "$YAML_KIND")" in singlenodeserver) return 0 ;; esac

  local value
  value="$(first_yaml_scalar "$CONFIG_FILE" spec.clusterMode spec.cluster-mode || true)"
  [[ "$value" == "single-node" || "$value" == "singleNode" || "$value" == "single" ]] && return 0

  value="$(first_yaml_scalar "$CONFIG_FILE" spec.singleNode.enabled spec.single-node.enabled || true)"
  bool_true "$value" && return 0

  return 1
}

cfg_value() {
  local default_value="$1"; shift
  local value=""
  if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
    value="$(first_yaml_scalar "$CONFIG_FILE" "$@" || true)"
  fi
  printf '%s\n' "${value:-$default_value}"
}

render_overlay() {
  local snapshot_cron snapshot_retention snapshot_dir
  local audit_age audit_backup audit_size ingress_controller
  snapshot_cron="$(cfg_value '0 */6 * * *' spec.singleNode.snapshotScheduleCron spec.single-node.snapshot-schedule-cron)"
  snapshot_retention="$(cfg_value '12' spec.singleNode.snapshotRetention spec.single-node.snapshot-retention)"
  snapshot_dir="$(cfg_value '/var/lib/rancher/rke2/server/db/snapshots' spec.singleNode.snapshotDir spec.single-node.snapshot-dir)"
  audit_age="$(cfg_value '30' spec.singleNode.auditLogMaxAge spec.single-node.audit-log-max-age)"
  audit_backup="$(cfg_value '10' spec.singleNode.auditLogMaxBackup spec.single-node.audit-log-max-backup)"
  audit_size="$(cfg_value '100' spec.singleNode.auditLogMaxSize spec.single-node.audit-log-max-size)"
  ingress_controller="$(cfg_value 'none' spec.singleNode.ingressController spec.ingress-controller spec.ingressController)"
  [[ "$ENABLE_INGRESS" -eq 0 ]] && ingress_controller="none"

  cat <<YAML
# Managed by bin/rke2-single-node-profile.sh.
# This file is intentionally a config.yaml.d drop-in so bin/rke2nodeinit.sh can
# continue owning the base /etc/rancher/rke2/config.yaml generated from rkeprep/v2.
write-kubeconfig-mode: "0600"
tls-san-security: true
secrets-encryption: true
secrets-encryption-provider: "aescbc"
etcd-snapshot-compress: true
etcd-snapshot-retention: ${snapshot_retention}
etcd-snapshot-schedule-cron: "${snapshot_cron}"
etcd-snapshot-dir: "${snapshot_dir}"
ingress-controller: "${ingress_controller}"

kube-apiserver-arg+:
  - "audit-log-maxage=${audit_age}"
  - "audit-log-maxbackup=${audit_backup}"
  - "audit-log-maxsize=${audit_size}"
  - "service-account-extend-token-expiration=false"
kube-controller-manager-arg+:
  - "terminated-pod-gc-threshold=100"
kubelet-arg+:
  - "event-qps=0"
YAML

  if [[ "$ENABLE_CIS" -eq 1 ]]; then
    cat <<'YAML'
profile: "cis"
protect-kernel-defaults: true
YAML
  fi

  if [[ "$PROFILE_MODE" == "dev" ]]; then
    cat <<'YAML'
# Dev mode keeps logs smaller and snapshots less aggressive. Use production mode
# when this node hosts anything other than disposable workloads.
YAML
  fi
}

render_coredns_config() {
  cat <<'YAML'
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-coredns
  namespace: kube-system
spec:
  valuesContent: |-
    replicaCount: 1
    resources:
      requests:
        cpu: 25m
        memory: 64Mi
      limits:
        cpu: 100m
        memory: 128Mi
YAML
}

render_metrics_server_config() {
  cat <<'YAML'
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-metrics-server
  namespace: kube-system
spec:
  valuesContent: |-
    resources:
      requests:
        cpu: 25m
        memory: 64Mi
      limits:
        cpu: 100m
        memory: 128Mi
YAML
}

render_snapshot_controller_config() {
  cat <<'YAML'
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-snapshot-controller
  namespace: kube-system
spec:
  valuesContent: |-
    resources:
      requests:
        cpu: 10m
        memory: 32Mi
      limits:
        cpu: 50m
        memory: 96Mi
YAML
}

render_default_network_policy() {
  cat <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Ingress
YAML
}

write_file() {
  local path="$1"
  local mode="$2"
  local content_file="$3"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN would write ${path}"
    sed 's/^/  | /' "$content_file" >&2
    return 0
  fi

  install -d -m 0755 "$(dirname -- "$path")"
  install -m "$mode" "$content_file" "$path"
  info "Wrote ${path}"
}

apply_cis_host_prereqs() {
  [[ "$ENABLE_CIS" -eq 1 ]] || return 0

  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "DRY-RUN would ensure local etcd user/group and install RKE2 CIS sysctl config when present"
    return 0
  fi

  if ! getent group etcd >/dev/null 2>&1; then
    groupadd --system etcd
    info "Created system group: etcd"
  fi
  if ! id etcd >/dev/null 2>&1; then
    useradd -r -c "etcd user" -s /usr/sbin/nologin -M -g etcd etcd
    info "Created system user: etcd"
  fi

  local src=""
  for candidate in /usr/local/share/rke2/rke2-cis-sysctl.conf /usr/share/rke2/rke2-cis-sysctl.conf; do
    if [[ -f "$candidate" ]]; then
      src="$candidate"
      break
    fi
  done

  if [[ -n "$src" ]]; then
    install -m 0644 "$src" /etc/sysctl.d/60-rke2-cis.conf
    systemctl restart systemd-sysctl.service 2>/dev/null || sysctl -p /etc/sysctl.d/60-rke2-cis.conf || true
    info "Installed RKE2 CIS sysctl configuration from ${src}"
  else
    warn "RKE2 CIS sysctl source not found yet; run this helper again after image staging or before first rke2-server start"
  fi
}

apply_profile() {
  if ! is_single_node_enabled; then
    fatal "YAML is not opted into single-node mode. Use kind: singleNodeServer, set spec.clusterMode: single-node, set spec.singleNode.enabled: true, or pass --force."
  fi

  local tmp
  tmp="$(mktemp)"
  render_overlay > "$tmp"
  write_file "${OUTPUT_DIR}/20-single-node-production.yaml" 0644 "$tmp"
  rm -f "$tmp"

  apply_cis_host_prereqs

  if [[ "$ENABLE_LOW_RESOURCE_MANIFESTS" -eq 1 ]]; then
    tmp="$(mktemp)"; render_coredns_config > "$tmp"; write_file "${MANIFEST_DIR}/rke2-coredns-config.yaml" 0644 "$tmp"; rm -f "$tmp"
    tmp="$(mktemp)"; render_metrics_server_config > "$tmp"; write_file "${MANIFEST_DIR}/rke2-metrics-server-config.yaml" 0644 "$tmp"; rm -f "$tmp"
    tmp="$(mktemp)"; render_snapshot_controller_config > "$tmp"; write_file "${MANIFEST_DIR}/rke2-snapshot-controller-config.yaml" 0644 "$tmp"; rm -f "$tmp"
  fi

  if [[ "$ENABLE_DEFAULT_NETWORK_POLICY" -eq 1 ]]; then
    tmp="$(mktemp)"; render_default_network_policy > "$tmp"; write_file "${MANIFEST_DIR}/single-node-default-deny-ingress.yaml" 0644 "$tmp"; rm -f "$tmp"
  fi

  info "Single-node RKE2 profile applied. Continue with: sudo bash bin/rke2nodeinit.sh server -f ${CONFIG_FILE:-<manifest>} -y"
}

verify_profile() {
  local rc=0
  local overlay="${OUTPUT_DIR}/20-single-node-production.yaml"
  if [[ -f "$overlay" ]]; then
    info "Found overlay: ${overlay}"
  else
    warn "Missing overlay: ${overlay}"
    rc=1
  fi

  local f
  for f in rke2-coredns-config.yaml rke2-metrics-server-config.yaml rke2-snapshot-controller-config.yaml single-node-default-deny-ingress.yaml; do
    if [[ -f "${MANIFEST_DIR}/${f}" ]]; then
      info "Found manifest: ${MANIFEST_DIR}/${f}"
    else
      warn "Missing manifest: ${MANIFEST_DIR}/${f}"
    fi
  done

  if [[ "$ENABLE_CIS" -eq 1 ]]; then
    getent passwd etcd >/dev/null 2>&1 || { warn "Missing etcd user required by CIS profile"; rc=1; }
    [[ -f /etc/sysctl.d/60-rke2-cis.conf ]] || warn "RKE2 CIS sysctl drop-in not present yet"
  fi

  return "$rc"
}

run_nodeinit() {
  local delegated_action="$1"
  shift || true
  [[ -n "$CONFIG_FILE" ]] || fatal "${delegated_action} action requires -f <rkeprep-yaml>"
  [[ -f "$CONFIG_FILE" ]] || fatal "Config file not found: $CONFIG_FILE"

  local nodeinit="${REPO_ROOT}/bin/rke2nodeinit.sh"
  [[ -f "$nodeinit" ]] || fatal "Cannot find ${nodeinit}"

  local -a args=("${delegated_action}" -f "$CONFIG_FILE")
  args+=("${NODEINIT_ARGS[@]}")

  info "Executing: bash ${nodeinit} ${args[*]}"
  exec bash "$nodeinit" "${args[@]}"
}

run_image_flow() {
  case "$(normalize_kind "$YAML_KIND")" in
    singlenodeimage|image) ;;
    *) fatal "image action requires kind: singleNodeImage or Image; found '${YAML_KIND:-<none>}'" ;;
  esac
  run_nodeinit image
}

run_server_flow() {
  case "$(normalize_kind "$YAML_KIND")" in
    singlenodeserver|server) ;;
    *) fatal "server action requires kind: singleNodeServer or Server; found '${YAML_KIND:-<none>}'" ;;
  esac
  apply_profile
  run_nodeinit server
}

main() {
  parse_args "$@"
  load_yaml_metadata
  load_yaml_overrides
  derive_action_from_kind
  validate_action

  case "$ACTION" in
    image) run_image_flow ;;
    server) run_server_flow ;;
    render) render_overlay ;;
    apply) apply_profile ;;
    verify) verify_profile ;;
  esac
}

main "$@"
