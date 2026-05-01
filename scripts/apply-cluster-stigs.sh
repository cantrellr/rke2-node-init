#!/usr/bin/env bash
# shellcheck disable=SC2155,SC1090
#
# apply-cluster-stigs.sh
#
# Purpose:
#   This script applies post‑deployment Kubernetes hardening actions based on
#   DISA STIG guidance.  It is designed to be run **after** all Kubernetes
#   workloads have been deployed (e.g. application Helm charts) so that
#   namespaces and workloads exist.  The script is intentionally generic
#   and does not assume a specific service mesh or Helm chart structure.
#
#   Hardened actions include:
#     • Setting Pod Security Standards labels on namespaces (restricted/baseline).
#     • Optionally applying a default deny NetworkPolicy to application namespaces.
#     • Optionally labeling namespaces with their own name for NetworkPolicy selectors.
#   These steps complement the host‑level and RKE2 configuration hardening
#   performed by scripts/apply-stigs.sh and k8s-node-firewalld-zone-hardening.sh.
#
# Usage examples:
#   # Dry run showing what would be done
#   ./apply-cluster-stigs.sh --dry-run
#
#   # Apply labels and default deny policies to explicit contexts and namespaces
#   ./apply-cluster-stigs.sh --yes \
#     --contexts "cluster1 cluster2" \
#     --namespaces "rocketchat mongodb nats-system monitoring" \
#     --apply-default-deny
#
#   # Label namespaces only
#   ./apply-cluster-stigs.sh --yes
#
# Exit codes:
#   0 - Success
#   1 - General/runtime error
#   2 - Invalid argument/configuration
#   3 - Preflight failure

set -Eeuo pipefail

# Default values
ASSUME_YES="false"
DRY_RUN="false"
APPLY_DEFAULT_DENY="false"
CONTEXTS=""
NAMESPACES="rocketchat mongodb nats-system monitoring keycloak postgres-system"

# Helper functions for colored output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

usage() {
  cat <<'USAGE'
Usage: $0 [options]

Apply post‑deployment Kubernetes hardening based on DISA STIG guidance.

Options:
  --yes                    Apply changes without interactive confirmation.  If
                           omitted, the script will prompt before making changes.
  --dry-run                Print actions without executing kubectl commands.
  --apply-default-deny     Deploy a default deny NetworkPolicy in each target
                           namespace.  This policy blocks all ingress/egress
                           traffic unless other policies are present.  Ensure
                           application‑specific policies are in place before
                           enabling.
  --contexts "ctx1 ctx2"    Space‑separated list of kubeconfig contexts to
                           operate on.  If omitted, all contexts returned by
                           `kubectl config get-contexts -o name` are used.
  --namespaces "ns1 ns2"    Space‑separated list of namespaces to label.  If
                           omitted, a reasonable default list of common
                           application namespaces is used (rocketchat mongodb
                           nats-system monitoring keycloak postgres-system).
  -h, --help               Show this help message.

The script must have access to kubectl and to a kubeconfig containing all
target contexts.  It should be run as a user with sufficient privileges to
label namespaces and create network policies.

USAGE
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)
      ASSUME_YES="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    --apply-default-deny)
      APPLY_DEFAULT_DENY="true"
      shift
      ;;
    --contexts)
      if [[ -n "${2:-}" ]]; then
        CONTEXTS="$2"
        shift 2
      else
        error "Missing argument for --contexts"
        exit 2
      fi
      ;;
    --namespaces)
      if [[ -n "${2:-}" ]]; then
        NAMESPACES="$2"
        shift 2
      else
        error "Missing argument for --namespaces"
        exit 2
      fi
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      error "Unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

# Preflight checks
if ! command -v kubectl >/dev/null 2>&1; then
  error "kubectl not found. Please install kubectl and configure a kubeconfig."
  exit 3
fi

# Determine contexts
if [[ -z "$CONTEXTS" ]]; then
  CONTEXTS="$(kubectl config get-contexts -o name | tr '\n' ' ')"
  if [[ -z "$CONTEXTS" ]]; then
    error "No kubeconfig contexts found."
    exit 3
  fi
fi

info "Target contexts: $CONTEXTS"
info "Target namespaces: $NAMESPACES"

# Show plan if not assuming yes
if [[ "$ASSUME_YES" != "true" ]]; then
  echo ""
  echo "=========================================="
  echo "Post‑Deployment STIG Hardening"
  echo "=========================================="
  echo "This script will perform the following actions:"
  echo "  • Label each namespace with Pod Security Standards enforcement:"
  echo "      \"pod-security.kubernetes.io/enforce=restricted\""
  echo "      \"pod-security.kubernetes.io/enforce-version=latest\""
  echo "  • Label each namespace with its own name for NetworkPolicy selectors"
  if [[ "$APPLY_DEFAULT_DENY" == "true" ]]; then
    echo "  • Apply a default deny NetworkPolicy to each namespace"
  else
    echo "  • Default deny NetworkPolicy will NOT be applied"
  fi
  echo ""
  read -p "Continue? (yes/no): " CONFIRM
  if [[ "$CONFIRM" != "yes" ]]; then
    warn "Operation cancelled by user."
    exit 0
  fi
fi

# Define default deny NetworkPolicy YAML (inline here to avoid external dependencies)
read -r -d '' DEFAULT_DENY_POLICY <<'EOF_POLICY'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
EOF_POLICY

# Loop through contexts and namespaces
for CONTEXT in $CONTEXTS; do
  info "Processing context: ${CONTEXT}"
  # Switch context
  if [[ "$DRY_RUN" != "true" ]]; then
    kubectl config use-context "$CONTEXT" >/dev/null 2>&1 || {
      error "Failed to switch context to ${CONTEXT}. Skipping."
      continue
    }
  else
    info "(dry‑run) Would run: kubectl config use-context ${CONTEXT}"
  fi
  for NS in $NAMESPACES; do
    # Skip if namespace does not exist
    if [[ "$DRY_RUN" == "true" ]]; then
      info "(dry‑run) Would check existence of namespace ${NS}"
    else
      if ! kubectl get namespace "$NS" >/dev/null 2>&1; then
        warn "Namespace ${NS} does not exist in ${CONTEXT}; skipping."
        continue
      fi
    fi

    # Apply Pod Security Standards labels
    if [[ "$DRY_RUN" == "true" ]]; then
      info "(dry‑run) Would label namespace ${NS} with PodSecurity enforcement"
    else
      kubectl label namespace "$NS" \
        pod-security.kubernetes.io/enforce=restricted \
        pod-security.kubernetes.io/enforce-version=latest \
        --overwrite >/dev/null 2>&1 || {
        warn "Failed to label namespace ${NS} in ${CONTEXT}"
      }
    fi

    # Label namespace with its name (useful for NetworkPolicy selectors)
    if [[ "$DRY_RUN" == "true" ]]; then
      info "(dry‑run) Would label namespace ${NS} kubernetes.io/metadata.name=${NS}"
    else
      kubectl label namespace "$NS" kubernetes.io/metadata.name="${NS}" --overwrite >/dev/null 2>&1 || {
        warn "Failed to label kubernetes.io/metadata.name for ${NS} in ${CONTEXT}"
      }
    fi

    # Apply default deny policy if requested
    if [[ "$APPLY_DEFAULT_DENY" == "true" ]]; then
      if [[ "$DRY_RUN" == "true" ]]; then
        info "(dry‑run) Would apply default deny NetworkPolicy in namespace ${NS}"
      else
        echo "$DEFAULT_DENY_POLICY" | kubectl apply -n "$NS" -f - >/dev/null 2>&1 || {
          warn "Failed to apply default deny policy in ${NS} in ${CONTEXT}"
        }
      fi
    fi
  done
done

info "Post‑deployment STIG hardening completed."