#!/usr/bin/env bash
# cleanup-rke2.sh
# Remove RKE2 and rke2-node-init artifacts. Must be run as root.

set -Eeuo pipefail

FORCE=0
DRY_RUN=0

while (( $# )); do
  case "$1" in
    -f|--force|-y|--yes)
      FORCE=1
      shift
      ;;
    -n|--dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: cleanup-rke2.sh [OPTIONS]

Options:
  -f, --force, -y, --yes   Skip confirmation prompt and remove files immediately (must run as root)
  -n, --dry-run            Show what would be removed but don't actually delete anything
  -h, --help               Show this help message
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: this script must be run as root (sudo)."
  exit 1
fi

# Directories to remove
declare -a targets=(
  "/etc/rancher/"
  "/opt/rke2/"
  "/rke2-node-init/downloads/"
  "/rke2-node-init/logs/"
  "/rke2-node-init/outputs/"
  "/var/lib/rancher/"
)

echo "The following directories will be permanently removed:"
for d in "${targets[@]}"; do
  echo "  $d"
done


if [[ $FORCE -ne 1 ]]; then
  read -r -p "Are you sure you want to continue? Type 'YES' to proceed: " confirm
  # Trim whitespace and convert to upper-case to allow 'yes', 'Yes', 'y', etc.
  confirm=$(printf '%s' "$confirm" | sed -e 's/^\s*//' -e 's/\s*$//' | tr '[:lower:]' '[:upper:]')
  if [[ "$confirm" != "YES" && "$confirm" != "Y" ]]; then
    echo "Aborting. No changes made."
    exit 0
  fi
else
  echo "--force provided; skipping confirmation prompt"
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "DRY RUN: no files will be deleted. The following would be removed:"
fi

# Perform removals
for d in "${targets[@]}"; do
  if [[ -e "$d" ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
      echo "Would remove: $d"
    else
      echo "Removing $d"
      rm -rf -- "$d"
    fi
  else
    echo "Not found: $d"
  fi
done

echo "Cleanup complete."
