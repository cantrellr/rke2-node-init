#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage:
  bash diagrams/render-mermaid-assets.sh [repo-root] [--install-deps] [--install-browser-deps]

Purpose:
  Render Mermaid source files from diagrams/mermaid-source into diagrams/svg and diagrams/png.

Notes:
  - Local Node tooling is installed under .diagram-tools when --install-deps is used.
  - Puppeteer/Chrome shared-library dependencies can be installed with --install-browser-deps.
USAGE
}

REPO_ROOT="."
INSTALL_DEPS=false
INSTALL_BROWSER_DEPS=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-deps) INSTALL_DEPS=true; shift ;;
    --install-browser-deps) INSTALL_BROWSER_DEPS=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) REPO_ROOT="$1"; shift ;;
  esac
done

REPO_ROOT="$(cd "$REPO_ROOT" && pwd -P)"
SRC_DIR="$REPO_ROOT/diagrams/mermaid-source"
SVG_DIR="$REPO_ROOT/diagrams/svg"
PNG_DIR="$REPO_ROOT/diagrams/png"
TOOLS_DIR="$REPO_ROOT/.diagram-tools"
PUPPETEER_CONFIG="$REPO_ROOT/diagrams/puppeteer-config.json"

mkdir -p "$SVG_DIR" "$PNG_DIR"

install_browser_deps() {
  if [[ $EUID -ne 0 ]]; then
    SUDO=sudo
  else
    SUDO=""
  fi
  $SUDO apt-get update
  $SUDO apt-get install -y \
    ca-certificates fonts-liberation libasound2t64 libatk-bridge2.0-0t64 \
    libatk1.0-0t64 libatspi2.0-0t64 libcairo2 libcups2t64 libdbus-1-3 \
    libdrm2 libexpat1 libfontconfig1 libgbm1 libglib2.0-0t64 libgtk-3-0t64 \
    libnspr4 libnss3 libpango-1.0-0 libpangocairo-1.0-0 libx11-6 \
    libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 \
    libxfixes3 libxi6 libxkbcommon0 libxrandr2 libxrender1 libxshmfence1 \
    libxss1 libxtst6 lsb-release wget xdg-utils
}

if [[ "$INSTALL_BROWSER_DEPS" == true ]]; then
  install_browser_deps
fi

if [[ "$INSTALL_DEPS" == true ]]; then
  mkdir -p "$TOOLS_DIR"
  if [[ ! -f "$TOOLS_DIR/package.json" ]]; then
    cat > "$TOOLS_DIR/package.json" <<'JSON'
{"private":true,"dependencies":{"@mermaid-js/mermaid-cli":"latest"}}
JSON
  fi
  npm --prefix "$TOOLS_DIR" install
fi

if [[ -x "$TOOLS_DIR/node_modules/.bin/mmdc" ]]; then
  MMDC="$TOOLS_DIR/node_modules/.bin/mmdc"
elif command -v mmdc >/dev/null 2>&1; then
  MMDC="$(command -v mmdc)"
else
  echo "ERROR: Mermaid CLI not found. Run with --install-deps." >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node is required for Mermaid CLI. Install Node.js or run without sudo if using nvm." >&2
  exit 1
fi

shopt -s nullglob
sources=("$SRC_DIR"/*.mmd)
if [[ ${#sources[@]} -eq 0 ]]; then
  echo "ERROR: no Mermaid sources found in $SRC_DIR" >&2
  exit 1
fi

echo "Rendering ${#sources[@]} Mermaid diagram(s) from $SRC_DIR"
for src in "${sources[@]}"; do
  base="$(basename "$src" .mmd)"
  echo "Rendering $base.svg"
  "$MMDC" -i "$src" -o "$SVG_DIR/$base.svg" -b transparent -t default -p "$PUPPETEER_CONFIG"
  echo "Rendering $base.png"
  "$MMDC" -i "$src" -o "$PNG_DIR/$base.png" -b transparent -t default -s 2 -p "$PUPPETEER_CONFIG"
done

echo "Mermaid SVG/PNG export rendering complete."
