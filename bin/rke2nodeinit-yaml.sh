#!/usr/bin/env bash
# YAML helper library for rkeprep/v2 manifests.

set -Eeuo pipefail

rkeprep_yaml_kind() {
  local file="${1:-}"
  [[ -n "$file" && -f "$file" ]] || return 1
  python3 - "$file" <<'PY'
import re
import sys
from pathlib import Path
path = Path(sys.argv[1])
for raw in path.read_text(encoding='utf-8').splitlines():
    line = raw.split('#', 1)[0].strip()
    if not line:
        continue
    m = re.match(r'^kind\s*:\s*["\']?([^"\']+)["\']?\s*$', line)
    if m:
        print(m.group(1).strip())
        raise SystemExit(0)
raise SystemExit(1)
PY
}

rkeprep_yaml_api_version() {
  local file="${1:-}"
  [[ -n "$file" && -f "$file" ]] || return 1
  python3 - "$file" <<'PY'
import re
import sys
from pathlib import Path
path = Path(sys.argv[1])
for raw in path.read_text(encoding='utf-8').splitlines():
    line = raw.split('#', 1)[0].strip()
    if not line:
        continue
    m = re.match(r'^apiVersion\s*:\s*["\']?([^"\']+)["\']?\s*$', line)
    if m:
        print(m.group(1).strip())
        raise SystemExit(0)
raise SystemExit(1)
PY
}

rkeprep_yaml_assert_v2() {
  local file="${1:-}"
  local api
  api="$(rkeprep_yaml_api_version "$file" || true)"
  [[ "$api" == "rkeprep/v2" ]] || {
    echo "ERROR: unsupported apiVersion '${api:-<none>}' in $file; expected rkeprep/v2" >&2
    return 1
  }
}

rkeprep_yaml_normalize_kind() {
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]_-'
}
