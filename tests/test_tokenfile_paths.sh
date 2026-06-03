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

# tokenFile paths must follow canonical nested contract under outputs.
while IFS= read -r hit; do
  [[ -n "$hit" ]] || continue

  token_path=""
  if [[ "$hit" =~ tokenFile:[[:space:]]*([^[:space:]#]+) ]]; then
    token_path="${BASH_REMATCH[1]}"
  fi
  [[ -n "$token_path" ]] || continue

  if [[ "$token_path" != /rke2-node-init/outputs/*/*-bootstrap-token.txt ]]; then
    echo "ERROR: tokenFile must match /rke2-node-init/outputs/<image>/<image>-bootstrap-token.txt: $hit"
    fail=1
    continue
  fi

  token_dir="$(basename -- "$(dirname -- "$token_path")")"
  token_base="$(basename -- "$token_path")"
  expected_base="${token_dir}-bootstrap-token.txt"
  if [[ "$token_base" != "$expected_base" ]]; then
    echo "ERROR: tokenFile basename must match parent image folder (${expected_base}): $hit"
    fail=1
  fi
done < <(grep -RIn "^[[:space:]]*tokenFile:[[:space:]]*/rke2-node-init/outputs/" "$root/configs" "$root/clusters" 2>/dev/null || true)

if [[ "$fail" -ne 0 ]]; then
  echo "One or more tokenFile paths are invalid for first-boot runtime." >&2
  exit 1
fi

echo "All tokenFile paths use canonical /rke2-node-init/outputs/<image>/<image>-bootstrap-token.txt locations."
