#!/usr/bin/env bash
#
# RKE2 config helper library for rke2nodeinit.
#
# This library is intentionally side-effect free until a function is called. It
# exists so config rendering, validation, and sanitation can move out of the core
# implementation incrementally.

set -Eeuo pipefail

rke2_config_default_file() {
  printf '%s\n' "/etc/rancher/rke2/config.yaml"
}

rke2_config_dropin_dir() {
  printf '%s\n' "/etc/rancher/rke2/config.yaml.d"
}

rke2_config_all_files() {
  local cfg dropin
  cfg="$(rke2_config_default_file)"
  dropin="$(rke2_config_dropin_dir)"

  [[ -f "$cfg" ]] && printf '%s\n' "$cfg"
  if [[ -d "$dropin" ]]; then
    find "$dropin" -maxdepth 1 -type f -name '*.yaml' | sort
  fi
}

rke2_config_remove_key_from_file() {
  local file="${1:-}"
  local key="${2:-}"
  [[ -n "$file" && -f "$file" && -n "$key" ]] || return 0

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$file" "$key" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
key = sys.argv[2]
pattern = re.compile(rf'^\s*{re.escape(key)}\s*:')
lines = path.read_text(encoding='utf-8').splitlines()
out = []
i = 0
changed = False
while i < len(lines):
    line = lines[i]
    if pattern.match(line):
        changed = True
        base_indent = len(line) - len(line.lstrip())
        i += 1
        while i < len(lines):
            nxt = lines[i]
            if not nxt.strip():
                i += 1
                continue
            indent = len(nxt) - len(nxt.lstrip())
            if indent > base_indent:
                i += 1
                continue
            break
        continue
    out.append(line)
    i += 1
if changed:
    path.write_text('\n'.join(out).rstrip() + '\n', encoding='utf-8')
PY
  else
    sed -i "/^[[:space:]]*${key}[[:space:]]*:/d" "$file" 2>/dev/null || true
  fi
}

rke2_config_sanitize_invalid_keys() {
  local file
  while IFS= read -r file; do
    rke2_config_remove_key_from_file "$file" "import-images"
  done < <(rke2_config_all_files)
}

rke2_config_assert_no_invalid_keys() {
  local rc=0
  local file
  while IFS= read -r file; do
    if grep -Eq '^[[:space:]]*import-images[[:space:]]*:' "$file"; then
      echo "ERROR: unsupported RKE2 config key import-images found in $file" >&2
      rc=1
    fi
  done < <(rke2_config_all_files)
  return "$rc"
}

rke2_config_write_dropin() {
  local name="${1:-}"
  local mode="${2:-0644}"
  local src="${3:-}"
  [[ -n "$name" && -n "$src" && -f "$src" ]] || return 2

  local dir path
  dir="$(rke2_config_dropin_dir)"
  path="${dir}/${name}"
  install -d -m 0755 "$dir"
  install -m "$mode" "$src" "$path"
}
