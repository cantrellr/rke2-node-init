#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: list-effective-rke2-images.sh [options]

Emit a sorted unique list of container image:tag references that are effectively
in play for this host by combining:
  1) downloads/rke2-images.linux-<arch>.txt
  2) downloads/chart-images-required.linux-<arch>.txt
  3) RepoTags found in staged archives under:
       - /var/lib/rancher/rke2/agent/images
       - /opt/rke2/stage

Options:
  --arch <arch>                 Architecture suffix (default: amd64 on x86_64)
  --downloads-dir <path>        Downloads directory (default: ./downloads)
  --agent-images-dir <path>     Agent images dir (default: /var/lib/rancher/rke2/agent/images)
  --stage-dir <path>            Stage dir (default: /opt/rke2/stage)
  --help                        Show this help
EOF
}

map_arch() {
  case "${1:-}" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "${1:-amd64}" ;;
  esac
}

ARCH="$(map_arch "$(uname -m 2>/dev/null || echo amd64)")"
DOWNLOADS_DIR="./downloads"
AGENT_IMAGES_DIR="/var/lib/rancher/rke2/agent/images"
STAGE_DIR="/opt/rke2/stage"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)
      ARCH="$(map_arch "${2:-}")"
      shift 2
      ;;
    --downloads-dir)
      DOWNLOADS_DIR="${2:-}"
      shift 2
      ;;
    --agent-images-dir)
      AGENT_IMAGES_DIR="${2:-}"
      shift 2
      ;;
    --stage-dir)
      STAGE_DIR="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

append_image_list_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  awk 'NF { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0); if ($0 != "") print $0 }' "$file" >> "$TMP_FILE"
}

append_repotags_from_archive() {
  local archive="$1"
  local manifest=""

  if [[ "$archive" == *.zst ]]; then
    if ! command -v zstd >/dev/null 2>&1; then
      return 0
    fi
    manifest="$(zstd -d -c "$archive" 2>/dev/null | tar -Ox manifest.json 2>/dev/null || true)"
  else
    manifest="$(tar -xOf "$archive" manifest.json 2>/dev/null || true)"
  fi

  [[ -n "$manifest" ]] || return 0

  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$manifest" >> "$TMP_FILE" 2>/dev/null || true
import json
import sys

raw = sys.argv[1]
try:
    doc = json.loads(raw)
except Exception:
    doc = []

for entry in doc if isinstance(doc, list) else []:
    tags = entry.get("RepoTags") or []
    for tag in tags:
        if tag:
            print(tag)
PY
  else
    printf '%s\n' "$manifest" \
      | grep -oE '"RepoTags"[[:space:]]*:[[:space:]]*\[[^]]*\]' \
      | tr ',' '\n' \
      | grep -oE '[A-Za-z0-9._/-]+:[A-Za-z0-9._+-]+' \
      >> "$TMP_FILE" || true
  fi
}

append_stage_archives_from_dir() {
  local dir="$1"
  [[ -d "$dir" ]] || return 0

  local archive
  while IFS= read -r archive; do
    [[ -n "$archive" ]] || continue
    append_repotags_from_archive "$archive"
  done < <(find "$dir" -maxdepth 1 -type f \( -name '*.tar' -o -name '*.tar.zst' -o -name '*.tzst' -o -name '*.zst' \) | sort)
}

append_image_list_file "$DOWNLOADS_DIR/rke2-images.linux-${ARCH}.txt"
append_image_list_file "$DOWNLOADS_DIR/chart-images-required.linux-${ARCH}.txt"
append_stage_archives_from_dir "$AGENT_IMAGES_DIR"
append_stage_archives_from_dir "$STAGE_DIR"

sort -u "$TMP_FILE" | sed '/^$/d'
