#!/usr/bin/env bash
# Integration test: verify that checksum verification succeeds when
# image files live in IMAGES_DIR and the sha256 manifest is in STAGE_DIR.

set -Eeuo pipefail

TMPROOT=$(mktemp -d)
trap 'rm -rf "$TMPROOT"' EXIT

STAGE_DIR="$TMPROOT/stage"
IMAGES_DIR="$TMPROOT/images"
mkdir -p "$STAGE_DIR" "$IMAGES_DIR"

# Create fake artifacts
printf 'fake image contents\n' > "$IMAGES_DIR/rke2-images.linux-amd64.tar.zst"
printf '#!/bin/sh\necho install\n' > "$STAGE_DIR/install.sh"
chmod +x "$STAGE_DIR/install.sh"

# Create a sha256 manifest in STAGE_DIR that references basenames (common case)
MANIFEST="$STAGE_DIR/sha256sum-amd64.txt"
# Write manifest entries using basenames (simulate remote manifest)
sha256sum "$IMAGES_DIR/rke2-images.linux-amd64.tar.zst" | sed "s|$IMAGES_DIR/||" > "$MANIFEST"
sha256sum "$STAGE_DIR/install.sh" | awk '{print $1 "  " $2}' >> "$MANIFEST"

# Build temporary normalized manifest mapping basenames to actual staged paths
TMP_MAN="$TMPROOT/tmp-manifest.txt"
> "$TMP_MAN"
while read -r h fn; do
  bn=$(basename "$fn")
  if [[ -f "$STAGE_DIR/$bn" ]]; then
    echo "$h  $STAGE_DIR/$bn"
  elif [[ -f "$IMAGES_DIR/$bn" ]]; then
    echo "$h  $IMAGES_DIR/$bn"
  else
    echo "$h  $bn"
  fi
done < <(awk '{print $1, $2}' "$MANIFEST") > "$TMP_MAN"

# Run verification
OUT="$TMPROOT/sha-check.out"
if sha256sum -c "$TMP_MAN" > "$OUT" 2>&1; then
  echo "PASS: verification succeeded"
  cat "$OUT"
  exit 0
else
  echo "FAIL: verification failed"
  cat "$OUT"
  exit 1
fi
