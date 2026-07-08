#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd -P)"
script="$root/bin/rke2nodeinit-core.sh"
render="$root/scripts/render_rke2_config.py"

if [[ ! -f "$script" ]]; then
  echo "Script not found: $script" >&2
  exit 2
fi

if [[ ! -x "$render" ]]; then
  echo "Render helper missing or not executable: $render" >&2
  exit 2
fi

key_count="$(grep -F -c 'TOKEN_FILE="$(yaml_spec_get_any "$CONFIG_FILE" tokenFile token-file || true)"' "$script" || true)"
if [[ "$key_count" -lt 3 ]]; then
  echo "ERROR: Expected tokenFile/token-file parsing to be normalized across server, agent, and add-server." >&2
  exit 1
fi

if ! grep -Fq "token_file = spec.get('tokenFile') or spec.get('token-file')" "$render"; then
  echo "ERROR: Render helper does not support both tokenFile and token-file." >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

cat > "$tmpdir/token-file-only.yaml" <<'YAML'
apiVersion: rkeprep/v2
kind: Agent
spec:
  token-file: /tmp/token-from-kebab.txt
YAML

out1="$($render "$tmpdir/token-file-only.yaml")"
if ! printf '%s\n' "$out1" | grep -q '^token-file: "/tmp/token-from-kebab.txt"$'; then
  echo "ERROR: Render helper did not emit token-file from spec.token-file." >&2
  exit 1
fi

cat > "$tmpdir/token-precedence.yaml" <<'YAML'
apiVersion: rkeprep/v2
kind: Agent
spec:
  token: supplied-inline-token
  token-file: /tmp/should-not-be-used.txt
YAML

out2="$($render "$tmpdir/token-precedence.yaml")"
if ! printf '%s\n' "$out2" | grep -q '^token: supplied-inline-token$'; then
  echo "ERROR: Render helper did not preserve token precedence over token-file." >&2
  exit 1
fi
if printf '%s\n' "$out2" | grep -q '^token-file:'; then
  echo "ERROR: Render helper emitted token-file despite token precedence." >&2
  exit 1
fi

echo "Token YAML key normalization checks passed."