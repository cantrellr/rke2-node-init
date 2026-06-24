#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/package-release.sh [vX.Y.Z]

Creates release archives under dist/ from the current git checkout.

Outputs:
  dist/rke2-node-init-<version>.tar.gz
  dist/rke2-node-init-<version>.zip
  dist/rke2-node-init-<version>.sha256
  dist/rke2-node-init-<version>.manifest.txt
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  if [[ -f VERSION ]]; then
    VERSION="$(tr -d '[:space:]' < VERSION)"
  else
    echo "ERROR: version argument is required when VERSION file is absent" >&2
    usage >&2
    exit 1
  fi
fi

if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9._-]+)?$ ]]; then
  echo "ERROR: version must look like v3.0.0; got '${VERSION}'" >&2
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: must be run from inside a git checkout" >&2
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

NAME="rke2-node-init-${VERSION}"
DIST_DIR="dist"
TAR_PATH="${DIST_DIR}/${NAME}.tar.gz"
ZIP_PATH="${DIST_DIR}/${NAME}.zip"
SHA_PATH="${DIST_DIR}/${NAME}.sha256"
MANIFEST_PATH="${DIST_DIR}/${NAME}.manifest.txt"

mkdir -p "${DIST_DIR}"
rm -f "${TAR_PATH}" "${ZIP_PATH}" "${SHA_PATH}" "${MANIFEST_PATH}"

COMMIT_SHA="$(git rev-parse HEAD)"
BRANCH_NAME="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
BUILD_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "${MANIFEST_PATH}" <<EOF
name=${NAME}
version=${VERSION}
commit=${COMMIT_SHA}
branch=${BRANCH_NAME}
build_utc=${BUILD_UTC}
source=git archive from current checkout
EOF

echo "Creating ${TAR_PATH}"
git archive --format=tar --prefix="${NAME}/" HEAD | gzip -9 > "${TAR_PATH}"

echo "Creating ${ZIP_PATH}"
git archive --format=zip --prefix="${NAME}/" HEAD -o "${ZIP_PATH}"

# Include manifest checksums but do not recursively include the checksum file itself before it exists.
echo "Creating ${SHA_PATH}"
sha256sum "${TAR_PATH}" "${ZIP_PATH}" "${MANIFEST_PATH}" > "${SHA_PATH}"

echo "Release package created:"
ls -lh "${TAR_PATH}" "${ZIP_PATH}" "${SHA_PATH}" "${MANIFEST_PATH}"
