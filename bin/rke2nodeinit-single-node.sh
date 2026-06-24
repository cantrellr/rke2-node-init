#!/usr/bin/env bash
#
# Internal single-node action helper for rke2nodeinit.sh.
#
# This helper intentionally reuses the existing single-node profile implementation
# while ensuring that any delegated legacy image/server call lands in
# rke2nodeinit-core.sh through the public dispatcher. That avoids recursive
# single-node dispatch while keeping the current single-node implementation
# isolated from the main entrypoint.

set -Eeuo pipefail
trap 'rc=$?; echo "[ERROR] ${BASH_SOURCE[0]} failed at line ${LINENO} with exit ${rc}" >&2; exit ${rc}' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROFILE_SCRIPT="${SCRIPT_DIR}/rke2-single-node-profile.sh"

if [[ ! -f "$PROFILE_SCRIPT" ]]; then
  echo "ERROR: Missing single-node profile implementation: $PROFILE_SCRIPT" >&2
  exit 1
fi

export RKE2NODEINIT_CORE_DELEGATE=1
exec bash "$PROFILE_SCRIPT" "$@"
