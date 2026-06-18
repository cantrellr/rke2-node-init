# RKE2 Node Init Diagrams

This folder follows the local Mermaid workflow used across the air-gap documentation repos.

## Folder Layout

| Path | Purpose |
| --- | --- |
| `mermaid-source/` | Source-of-truth Mermaid files. |
| `svg/` | Generated SVG exports. |
| `png/` | Generated PNG exports. |
| `DIAGRAM-INDEX.md` | Human-readable diagram inventory. |
| `render-mermaid-assets.sh` | Local Mermaid renderer. |
| `apply-diagram-updates.sh` | Wrapper for rendering and staging diagram changes. |

## Render Locally

From the repo root:

```bash
bash diagrams/apply-diagram-updates.sh . --install-deps --install-browser-deps
bash diagrams/apply-diagram-updates.sh .
```

The first command installs local Mermaid CLI dependencies under `.diagram-tools/` if needed. The second command is the normal repeat run.

## Rules

- Do not commit fake placeholder diagram exports.
- Commit `.mmd` source and rendered SVG/PNG together.
- Keep `docs/System-Design-Document.md` export links aligned with this folder.
- Review generated SVG/PNG before pushing if diagrams changed.
