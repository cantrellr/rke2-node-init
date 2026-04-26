README Standardization Status

Date: April 24, 2026

Purpose:
This document tracks README normalization efforts and confirms current canonical command paths and cross-reference expectations.

Scope:
- root README.md
- scripts/certs/README.md
- examples/config/README.md
- scripts/wsl-env/WSL-DEV-SETUP.md
- vm/docs/README.md
- any other README*.md found under subfolders

Standard README structure (template):
1. Short summary (1-2 lines)
2. Table of Contents (anchors)
3. Quick start (copyable commands)
4. Examples (link to examples/*)
5. Security notes (if applicable)
6. Files & layout
7. Getting help / Contributing

Current standardization checks:
1. Identify all README files
2. Ensure command paths match current tree (`bin/`, `examples/config/`, `scripts/wsl-env/`)
3. Ensure certificate docs reference `scripts/certs/*` directly
4. Validate cross-links and refresh metadata dates

Checklist (current cycle):
- [x] Find README files across repo
- [x] Draft per-file patches
- [x] Apply patches and validate links/references
- [ ] Commit and push

Notes:
- Historical redesign docs under `docs/redesign/` are retained as archive content.
- Canonical current references should point to root README, docs index, and examples/config README.

