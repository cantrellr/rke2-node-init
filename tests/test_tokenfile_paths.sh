#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd -P)"
fail=0

expected="/etc/rancher/rke2/token.d/bootstrap.token"

# tokenFile/token-file must always resolve to the canonical protected host path.
while IFS= read -r hit; do
  [[ -n "$hit" ]] || continue

  token_path=""
  if [[ "$hit" =~ (tokenFile|token-file):[[:space:]]*([^[:space:]#]+) ]]; then
    token_path="${BASH_REMATCH[2]}"
  fi
  [[ -n "$token_path" ]] || continue

  if [[ "$token_path" != "$expected" ]]; then
    echo "ERROR: token file reference must be $expected: $hit"
    fail=1
  fi
done < <(grep -ERIn "^[[:space:]]*(tokenFile|token-file):" "$root/configs" "$root/clusters" 2>/dev/null || true)

if [[ "$fail" -ne 0 ]]; then
  echo "One or more tokenFile paths are invalid for first-boot runtime." >&2
  exit 1
fi

echo "All tokenFile paths use canonical $expected location."
