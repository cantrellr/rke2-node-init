#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd -P)"
script="$root/bin/rke2nodeinit.sh"

if [[ ! -f "$script" ]]; then
  echo "Script not found: $script" >&2
  exit 2
fi

resolve_calls="$(grep -F -c 'resolved_token_file="$(resolve_token_file_path "$TOKEN_FILE" || true)"' "$script" || true)"
if [[ "$resolve_calls" -lt 3 ]]; then
  echo "ERROR: Expected resolve_token_file_path usage in all three actions." >&2
  exit 1
fi

missing_errors="$(grep -F -c 'log_error "Token file provided but unavailable: $TOKEN_FILE"' "$script" || true)"
if [[ "$missing_errors" -lt 3 ]]; then
  echo "ERROR: Missing strict token-file errors for one or more actions." >&2
  exit 1
fi

remediation_errors="$(grep -F -c 'log_error "Remediation: provide a readable absolute path or a path relative to the manifest/repository root."' "$script" || true)"
if [[ "$remediation_errors" -lt 3 ]]; then
  echo "ERROR: Missing remediation guidance for one or more actions." >&2
  exit 1
fi

if grep -Fq 'Falling back to generated first-server bootstrap token.' "$script"; then
  echo "ERROR: Strict token-file policy regression: server fallback message still present." >&2
  exit 1
fi

if grep -Fq 'Using fallback generated secure first-server token (custom CA fingerprint embedded).' "$script"; then
  echo "ERROR: Strict token-file policy regression: secure fallback generation log still present." >&2
  exit 1
fi

if grep -Fq 'Using fallback generated short first-server bootstrap token.' "$script"; then
  echo "ERROR: Strict token-file policy regression: short fallback generation log still present." >&2
  exit 1
fi

if grep -Fq 'setup_custom_cluster_ca || true' "$script"; then
  echo "ERROR: customCA seeding failure is still being swallowed with || true." >&2
  exit 1
fi

if ! grep -Fq 'validate_prebuilt_token_custom_ca()' "$script"; then
  echo "ERROR: prebuilt customCA token validation helper is missing." >&2
  exit 1
fi

if ! grep -Fq 'Prebuilt token CA hash matches configured custom CA' "$script"; then
  echo "ERROR: prebuilt customCA token match logging is missing." >&2
  exit 1
fi

if grep -Fq 'Downloading helper to generate custom CA set (one-time).' "$script"; then
  echo "ERROR: Runtime customCA helper network fallback is still present." >&2
  exit 1
fi

if grep -Fq 'Custom CA generation failed via curl; leaving defaults in place.' "$script"; then
  echo "ERROR: Runtime customCA curl fallback failure path is still present." >&2
  exit 1
fi

if ! grep -Fq 'Runtime customCA seeding is offline-only. Populate helper during image process.' "$script"; then
  echo "ERROR: Offline-only customCA runtime remediation message is missing." >&2
  exit 1
fi

if ! grep -Fq 'Using generated secure first-server token (custom CA fingerprint embedded).' "$script"; then
  echo "ERROR: First-server generation path appears to be missing." >&2
  exit 1
fi

if ! grep -Fq 'Using generated short first-server bootstrap token.' "$script"; then
  echo "ERROR: First-server short token generation path appears to be missing." >&2
  exit 1
fi

echo "Strict token-file policy checks passed."