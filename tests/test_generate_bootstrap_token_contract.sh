#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd -P)"
script="$root/bin/rke2nodeinit.sh"

if [[ ! -f "$script" ]]; then
  echo "Script not found: $script" >&2
  exit 2
fi

# Guard against regressions where secure token generation sets global token
# but does not emit stdout, which breaks command-substitution call sites.
if grep -q "#  printf '%s' \"\$token\"" "$script"; then
  echo "ERROR: generate_bootstrap_token stdout emit is commented out." >&2
  exit 1
fi

if ! grep -q "printf '%s' \"\$token\"" "$script"; then
  echo "ERROR: generate_bootstrap_token does not print token to stdout." >&2
  exit 1
fi

if ! grep -q "token=\"\$passphrase\"" "$script"; then
  echo "ERROR: generate_bootstrap_token does not assign short token to global token variable." >&2
  exit 1
fi

echo "generate_bootstrap_token stdout/global token contract checks passed."
