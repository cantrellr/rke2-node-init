#!/usr/bin/env bash
set -Eeuo pipefail

REPO_ROOT="."
ARGS=()

if [[ $# -gt 0 && "$1" != --* ]]; then
  REPO_ROOT="$1"
  shift
fi

while [[ $# -gt 0 ]]; do
  ARGS+=("$1")
  shift
done

REPO_ROOT="$(cd "$REPO_ROOT" && pwd -P)"

bash "$REPO_ROOT/diagrams/render-mermaid-assets.sh" "$REPO_ROOT" "${ARGS[@]}"

mermaid_count="$(grep -c '```mermaid' "$REPO_ROOT/docs/System-Design-Document.md" || true)"
export_count="$(grep -c 'Diagram export:' "$REPO_ROOT/docs/System-Design-Document.md" || true)"
source_count="$(find "$REPO_ROOT/diagrams/mermaid-source" -maxdepth 1 -name '*.mmd' | wc -l | tr -d ' ')"

if [[ "$mermaid_count" != "$export_count" || "$mermaid_count" != "$source_count" ]]; then
  echo "ERROR: diagram drift detected." >&2
  echo "  Mermaid blocks : $mermaid_count" >&2
  echo "  Export lines   : $export_count" >&2
  echo "  Source files   : $source_count" >&2
  exit 1
fi

if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$REPO_ROOT" add docs/System-Design-Document.md diagrams/DIAGRAM-INDEX.md diagrams/mermaid-source diagrams/svg diagrams/png diagrams/README.md
  if ! git -C "$REPO_ROOT" diff --cached --quiet; then
    git -C "$REPO_ROOT" commit -m "Synchronize Mermaid diagram documentation and exports"
  else
    echo "No diagram changes to commit."
  fi
fi
