#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd -P)"
fail=0

# tokenFile paths under /rke2-node-init/configs are not runtime-safe for cloned nodes.
while IFS= read -r hit; do
  [[ -n "$hit" ]] || continue
  echo "ERROR: tokenFile points to /rke2-node-init/configs (should be /rke2-node-init/outputs): $hit"
  fail=1
done < <(grep -RIn "^[[:space:]]*tokenFile:[[:space:]]*/rke2-node-init/configs/" "$root/configs" "$root/clusters" 2>/dev/null || true)

if [[ "$fail" -ne 0 ]]; then
  echo "One or more tokenFile paths are invalid for first-boot runtime." >&2
  exit 1
fi

echo "All tokenFile paths avoid /rke2-node-init/configs runtime locations."
