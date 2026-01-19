#!/usr/bin/env bash
# Simple test: run the render helper against all YAML manifests under configs/ and clusters/
# Fail if any rendered fragment contains more than one 'token-file:' line.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
render="$root/scripts/render_rke2_config.py"
if [[ ! -x "$render" ]]; then
  echo "Render helper missing or not executable: $render" >&2
  exit 2
fi
fail=0
# Search common manifest directories
manifests=$(find "$root" -type f -name "*.yaml" -o -name "*.yml")
for m in $manifests; do
  out="$($render "$m" 2>/dev/null || true)"
  # count token-file occurrences
  cnt=$(printf "%s" "$out" | grep -c '^token-file:') || true
  if [[ "$cnt" -gt 1 ]]; then
    echo "ERROR: Duplicate token-file detected in manifest: $m (count=$cnt)"
    printf "%s\n" "$out" | sed -n '1,200p'
    fail=1
  fi
done
if [[ "$fail" -eq 1 ]]; then
  echo "One or more manifests render duplicate token-file entries." >&2
  exit 1
fi
echo "All manifests rendered without duplicate token-file lines."
