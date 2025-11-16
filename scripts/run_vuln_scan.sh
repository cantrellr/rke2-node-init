#!/usr/bin/env bash
# Minimal helper to run Trivy filesystem scans against a list of artifacts and
# emit a combined JSON report. This is a scaffold for the follow-up PR.

set -Eeuo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <output-json> <file-or-dir> [<file-or-dir> ...]"
  exit 2
fi

OUT_JSON="$1"; shift
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Ensure trivy if available
if ! command -v trivy >/dev/null 2>&1; then
  echo "WARN: trivy not found in PATH; vulnerability scanning skipped" >&2
  jq -n '{scanned: false, reason: "trivy-not-found"}' >"$OUT_JSON" || true
  exit 0
fi

# Run trivy in JSON mode for each target and aggregate results.
# Note: this is a simple aggregator; a full implementation should merge vulnerability
# records with deduplication logic.

echo '{"scanned": true, "results": [' >"$OUT_JSON"
local_first=1
for target in "$@"; do
  if [[ ! -e "$target" ]]; then
    echo "WARN: target not found: $target" >&2
    continue
  fi
  TMP_OUT="$TMPDIR/$(basename "$target").json"
  trivy fs --quiet --security-checks vuln --format json -o "$TMP_OUT" "$target" || true
  if [[ -f "$TMP_OUT" ]]; then
    if [[ $local_first -eq 1 ]]; then
      cat "$TMP_OUT" >>"$OUT_JSON"
      local_first=0
    else
      # Append without leading '['
      echo "," >>"$OUT_JSON"
      cat "$TMP_OUT" >>"$OUT_JSON"
    fi
  fi
done

echo ']}' >>"$OUT_JSON"

echo "WROTE_VULN_JSON $OUT_JSON"
