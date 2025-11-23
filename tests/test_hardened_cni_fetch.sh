#!/usr/bin/env bash
set -euo pipefail

# Quick integration-style test for hardened-cni manifest append logic.
# Does not require root. Creates a small tarball, serves it over HTTP,
# downloads it to a temp DOWNLOADS_DIR, computes sha256, appends to
# $DOWNLOADS_DIR/$SHA256_FILE, copies manifest to STAGE_DIR and runs
# sha256sum -c to validate.

TMPROOT=$(mktemp -d)
trap 'rm -rf "$TMPROOT"' EXIT

DOWNLOADS_DIR="$TMPROOT/downloads"
STAGE_DIR="$TMPROOT/stage"
mkdir -p "$DOWNLOADS_DIR" "$STAGE_DIR"

ARCH="amd64"
SHA256_FILE="sha256sum-$ARCH.txt"
BN="hardened-cni-plugins-${ARCH}.tar"

# Create a tiny tarball to serve
mkdir -p "$TMPROOT/serve"
echo "hello" > "$TMPROOT/serve/readme.txt"
tar -C "$TMPROOT/serve" -cf "$TMPROOT/$BN" readme.txt

# Start a simple HTTP server to serve the tarball
pushd "$TMPROOT" >/dev/null
PYPORT=0
# Find a free port by letting python choose one via --bind 127.0.0.1
python3 -m http.server 0 --bind 127.0.0.1 >/dev/null 2>&1 &
PID=$!
# Wait briefly for server to start
sleep 0.5
# Discover chosen port
# ps output contains the command line; use lsof or ss would be better, but parse python output
PORT=$(ss -ltnp | awk -v pid=$PID '$0 ~ pid {gsub(/.*:/, "", $4); print $4; exit}' || true)
if [[ -z "$PORT" ]]; then
  # fallback: try common port 8000
  PORT=8000
fi
SERVER_URL="http://127.0.0.1:$PORT/$BN"

# Attempt download using curl or wget
if command -v curl >/dev/null 2>&1; then
  curl -sSf -o "$DOWNLOADS_DIR/$BN" "$SERVER_URL"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$DOWNLOADS_DIR/$BN" "$SERVER_URL"
else
  echo "neither curl nor wget available" >&2
  kill $PID 2>/dev/null || true
  exit 2
fi

# Stop HTTP server
kill $PID 2>/dev/null || true
popd >/dev/null

# Compute sha and append to manifest idempotently (same logic used by script)
sha=$(sha256sum "$DOWNLOADS_DIR/$BN" | awk '{print $1}')
manifest="$DOWNLOADS_DIR/$SHA256_FILE"
if [[ -f "$manifest" ]]; then
  tmp=$(mktemp)
  grep -v -F " $BN" "$manifest" > "$tmp" || true
  printf "%s  %s\n" "$sha" "$BN" >> "$tmp"
  mv "$tmp" "$manifest"
else
  printf "%s  %s\n" "$sha" "$BN" > "$manifest"
fi

# Copy manifest to stage and validate using sha256sum -c
cp "$manifest" "$STAGE_DIR/"
# Also stage the downloaded tar so sha256sum -c can validate it as staged
cp "$DOWNLOADS_DIR/$BN" "$STAGE_DIR/"
# sha256sum -c expects files to be reachable by the paths in the manifest; ensure it points at the staged file
# Create a temporary manifest mapping the basename to its staged location
tmp_manifest=$(mktemp)
while read -r h fn; do
  bn2=$(basename "$fn")
  echo "$h  $STAGE_DIR/$bn2" >> "$tmp_manifest"
done < "$STAGE_DIR/$SHA256_FILE"

if sha256sum -c "$tmp_manifest" >/dev/null 2>&1; then
  echo "TEST PASS: hardened-cni manifest entry validated"
  exit 0
else
  echo "TEST FAIL: sha256sum -c failed" >&2
  exit 1
fi
