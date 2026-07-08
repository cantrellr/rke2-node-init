#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd -P)"
script="$root/bin/rke2nodeinit-core.sh"

if [[ ! -f "$script" ]]; then
  echo "Script not found: $script" >&2
  exit 2
fi

if ! grep -Fq 'REPO_CLEANUP_ALLOW_PATH="/rke2-node-init"' "$script"; then
  echo "ERROR: Repo cleanup allow-list path is missing or changed." >&2
  exit 1
fi

if ! grep -Fq 'ARTIFACT_RETENTION_ROOT="${ARTIFACT_RETENTION_ROOT:-/var/lib/rke2-node-init/artifacts}"' "$script"; then
  echo "ERROR: Artifact retention root default is missing." >&2
  exit 1
fi

if ! grep -Fq 'ARTIFACT_RETENTION_LOG_DIR="${ARTIFACT_RETENTION_LOG_DIR:-/var/log/rke2-node-init}"' "$script"; then
  echo "ERROR: Artifact retention log directory default is missing." >&2
  exit 1
fi

if ! grep -Fq 'retain_operational_artifacts()' "$script"; then
  echo "ERROR: Artifact retention function is missing." >&2
  exit 1
fi

if ! grep -Fq 'if [[ -d "$SBOM_DIR" ]]; then' "$script"; then
  echo "ERROR: SBOM retention copy logic is missing." >&2
  exit 1
fi

if ! grep -Fq 'if [[ -z "$repo_real" || "$repo_real" != "$REPO_CLEANUP_ALLOW_PATH" || "$repo_real" == "/" ]]; then' "$script"; then
  echo "ERROR: Repo cleanup path safety guard is missing." >&2
  exit 1
fi

if ! grep -Fq 'rm -rf --one-file-system "$repo_real"' "$script"; then
  echo "ERROR: Guarded repo cleanup delete operation is missing." >&2
  exit 1
fi

schedule_calls="$(grep -F -c 'schedule_post_success_cleanup "' "$script" || true)"
if [[ "$schedule_calls" -lt 3 ]]; then
  echo "ERROR: Expected cleanup scheduling for server, agent, and add-server." >&2
  exit 1
fi

execute_calls="$(grep -F -c 'execute_pending_post_success_cleanup' "$script" || true)"
if [[ "$execute_calls" -lt 3 ]]; then
  echo "ERROR: Expected deferred cleanup execution in reboot prompt paths." >&2
  exit 1
fi

echo "Repo cleanup contract checks passed."
